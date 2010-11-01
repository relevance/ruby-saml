require "rexml/document"
require "xml_sec"

module Onelogin::Saml
  class Response
    def initialize(response)
      @response = response
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(@response))
    end
    
    def logger=(val)
      @logger = val
    end
    
    def settings=(_settings)
      @settings = _settings
    end
    
    def is_valid?
      if @settings.idp_cert_fingerprint && !@response.nil?
        @document.validate(@settings.idp_cert_fingerprint, @logger)
      end
    end

    def name_id
      plaintext_name_id = @document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"]
      if plaintext_name_id
        return plaintext_name_id.text
      else
        cert_rsa = OpenSSL::PKey::RSA.new(@settings.private_key, @settings.private_key_password)
        encrypted_aes_key_element = @document.elements["/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue"]
        encrypted_aes_key = Base64.decode64(encrypted_aes_key_element.text)
        aes_key = cert_rsa.private_decrypt(encrypted_aes_key)
        encrypted_assertion = Base64.decode64(@document.elements["/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue"].text)
        aes_cipher = OpenSSL::Cipher.new("AES-128-CBC").decrypt
        iv = encrypted_assertion[0..15]
        data = encrypted_assertion[16..-1] 
        aes_cipher.padding = 0
        aes_cipher.key = aes_key
        aes_cipher.iv = iv
        assertion_plaintext = aes_cipher.update(data)
        assertion_plaintext << aes_cipher.final
        # We get some problematic noise in the plaintext after decrypting.
        # This quick regexp parse will grab only the assertion and discard the noise.
        assertion_plaintext =~ /(.*<\/saml:Assertion>)/m
        assertion_plaintext = $1
        assertion_doc = REXML::Document.new(assertion_plaintext)
        assertion_doc.elements["/saml:Assertion/saml:Subject/saml:NameID"].text
      end
    end

    def attributes
      @document.saml_attributes
    end

    def [](key)
      self.attributes[key]
    end
  end
end
