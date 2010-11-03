require "rexml/document"
require "rexml/xpath"
require "xml_sec"

module Onelogin::Saml
  class Response

    attr_accessor :expected_transaction_id
    attr_writer :logger
    attr_writer :settings
    
    def initialize(response, opts = {})
      @response = response
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(@response))
      if opts.has_key?(:expected_transaction_id)
        @expected_transaction_id = opts[:expected_transaction_id]
      end
    end
    
    def is_valid?
      valid = true
      valid &&= @document.validate_fingerprint(@settings.idp_cert_fingerprint, @logger) if @settings.idp_cert_fingerprint
      valid &&= @document.validate_digests(@logger)
      valid &&= @document.validate_signature(@logger)
      valid &&= within_time_window?
      valid &&= transaction_id_sync?
      return valid
    end

    alias :valid? :is_valid?
    alias :is_valid :is_valid?

    def encrypted?
      !!@document.elements[ENCRYPTED_RESPONSE_DATA_PATH]
    end

    def name_id
      return assertion_doc.elements[NAME_ID_PATH].text
    end

    def attributes
      saml_attributes = {}

      each_saml_attribute(assertion_doc,"./saml:AttributeStatement") do |statement_element|
        each_saml_attribute(statement_element, "./saml:Attribute") do |attribute_element|
          each_saml_attribute(attribute_element, "./saml:AttributeValue") do |value_element|
            attr_name = attribute_element.attributes["Name"]            
            saml_attributes[attr_name] = value_element.text
          end
        end
      end
      
      saml_attributes
    end

    def [](key)
      self.attributes[key]
    end

    private

    NAME_ID_PATH = "./saml:Subject/saml:NameID"
    PLAINTEXT_ASSERTION_PATH = "/samlp:Response/saml:Assertion"
    ENCRYPTED_RESPONSE_DATA_PATH = "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/"
    ENCRYPTED_AES_KEY_PATH = "./ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue"
    ENCRYPTED_ASSERTION_PATH = "./xenc:CipherData/xenc:CipherValue"
    SUBJECT_CONFIRMATION_DATA_PATH = "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData"

    def transaction_id
      confirmation_element = assertion_doc.elements[SUBJECT_CONFIRMATION_DATA_PATH]
      confirmation_element.attribute("InResponseTo").value
    end

    def samlp_transaction_id
      samlp_response = @document.root
      samlp_response.attribute("InResponseTo").value
    end
    
    def transaction_id_sync?
      return false unless transaction_id == samlp_transaction_id
      return true unless @expected_transaction_id
      transaction_id == @expected_transaction_id
    end

    def within_time_window?
      conditions_element = assertion_doc.elements["./saml:Conditions"]
      time_window_open = Time.parse(conditions_element.attribute("NotBefore").value)
      time_window_close = Time.parse(conditions_element.attribute("NotOnOrAfter").value)
      now = Time.now
      now >= time_window_open && now < time_window_close
    end

    def each_saml_attribute(element, selector, &blk)
      REXML::XPath.each(element, selector, {"saml" => "urn:oasis:names:tc:SAML:2.0:assertion"},  &blk)
    end

    def assertion_doc
      @assertion_doc ||= @document.elements[PLAINTEXT_ASSERTION_PATH]
      @assertion_doc = decrypt_assertion_document if @assertion_doc.nil?
      @assertion_doc
    end

    def retrieve_symmetric_key(cipher_data)
      cert_rsa = OpenSSL::PKey::RSA.new(@settings.private_key, @settings.private_key_password)
      encrypted_aes_key_element = cipher_data.elements[ENCRYPTED_AES_KEY_PATH]
      encrypted_aes_key = Base64.decode64(encrypted_aes_key_element.text)
      cert_rsa.private_decrypt(encrypted_aes_key)
    end

    def retrieve_plaintext(cipher_text, key)
      aes_cipher = OpenSSL::Cipher.new("AES-128-CBC").decrypt
      iv = cipher_text[0..15]
      data = cipher_text[16..-1] 
      aes_cipher.padding, aes_cipher.key, aes_cipher.iv = 0, key, iv
      assertion_plaintext = aes_cipher.update(data)
      assertion_plaintext << aes_cipher.final
      # We get some problematic noise in the plaintext after decrypting.
      # This quick regexp parse will grab only the assertion and discard the noise.
      assertion_plaintext =~ /(.*<\/saml:Assertion>)/m
      $1
    end

    def decrypt_assertion_document
      @encrypted = true
      cipher_data = @document.elements[ENCRYPTED_RESPONSE_DATA_PATH]
      aes_key = retrieve_symmetric_key(cipher_data)
      encrypted_assertion = Base64.decode64(cipher_data.elements[ENCRYPTED_ASSERTION_PATH].text)
      assertion_plaintext = retrieve_plaintext(encrypted_assertion, aes_key)
      assertion_doc = REXML::Document.new(assertion_plaintext).elements["/saml:Assertion"]
    end
    
  end
end
