require 'rexml/document'
require 'openssl/x509'
require 'digest/sha1'

module Onelogin::Saml
  class Settings
    attr_writer :assertion_consumer_service_url
    attr_writer :issuer
    attr_accessor :sp_name_qualifier
    attr_writer :idp_sso_target_url
    attr_writer :idp_cert_fingerprint
    attr_writer :name_identifier_format
    attr_reader :private_key
    attr_accessor :private_key_password

    def private_key=(keyfile)
      if keyfile.respond_to?(:read)
        @private_key = keyfile.read
      elsif File.exists?(keyfile)
        File.open(keyfile) { |file| @private_key = file.read }
      else
        @private_key = keyfile
      end
    end

    def idp_metadata=(metadata)
      if metadata.respond_to?(:read)
        @idp_metadata = metadata.read
      elsif File.exists?(metadata)
        File.open(metadata) { |file| @idp_metadata = file.read }
      else
        @idp_metadata = metadata
      end
    end

    alias :identity_provider_metadata= :idp_metadata=

    def sp_metadata=(metadata)
      if metadata.respond_to?(:read)
        @sp_metadata = metadata.read
      elsif File.exists?(metadata)
        File.open(metadata) { |file| @sp_metadata = file.read }
      else
        @sp_metadata = metadata
      end
    end

    alias :service_provider_metadata= :sp_metadata=
    
    def sp_yaml=(yaml)
      if yaml.respond_to?(:read)
        @sp_yaml = yaml.read
      elsif File.exists?(yaml)
        File.open(yaml) { |file| @sp_yaml = file.read}
      else
        @sp_yaml = yaml
      end
    end

    alias :service_provider_yaml= :sp_yaml=

    def idp_sso_target_url
      @idp_sso_target_url || idp_sso_target_url_from_metadata
    end

    def idp_cert_fingerprint
      @idp_cert_fingerprint || idp_cert_fingerprint_from_metadata
    end

    def issuer
      @issuer || issuer_from_config
    end

    def assertion_consumer_service_url
      @assertion_consumer_service_url || assertion_consumer_service_url_from_config
    end

    def name_identifier_format
      @name_identifier_format || name_identifier_format_from_config
    end

    private

    SSO_ELEMENT_PATH = "/EntityDescriptor/IDPSSODescriptor/SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']"
    X509_CERT_PATH = "/EntityDescriptor/IDPSSODescriptor/KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate"
    ENTITY_DESCRIPTOR_PATH = "/EntityDescriptor"
    ASSERTION_CONSUMER_PATH = "/EntityDescriptor/SPSSODescriptor/AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']"
    NAME_IDENTIFIER_PATH = "/EntityDescriptor/SPSSODescriptor/NameIDFormat"

    def idp_metadata_doc
      @idp_metadata_doc ||= REXML::Document.new(@idp_metadata)
    end

    def sp_metadata_doc
      @sp_metadata_doc ||= REXML::Document.new(@sp_metadata)
    end

    def parsed_sp_yaml
      @parsed_sp_yaml ||= YAML::load(@sp_yaml)
    end

    def name_identifier_format_from_config
      if @sp_metadata
        name_identifier_format_from_metadata
      elsif @sp_yaml
        name_identifier_format_from_yaml
      end
    end

    def name_identifier_format_from_yaml
      format_val = parsed_sp_yaml["name_id_format"]
      if format_val.respond_to?(:first)
        format_val.first
      else
        format_val
      end
    end
    
    def name_identifier_format_from_metadata
      name_identifier_element = sp_metadata_doc.elements[NAME_IDENTIFIER_PATH]
      name_identifier_element.text
    end

    def assertion_consumer_service_url_from_config
      if @sp_metadata
        assertion_consumer_service_url_from_metadata
      elsif @sp_yaml
        assertion_consumer_service_url_from_yaml
      end
    end

    def assertion_consumer_service_url_from_yaml
      parsed_sp_yaml["consumer_url"]
    end

    def assertion_consumer_service_url_from_metadata
      assertion_consumer_element = sp_metadata_doc.elements[ASSERTION_CONSUMER_PATH]
      assertion_consumer_element.attribute('Location').value
    end

    def issuer_from_config
      if @sp_metadata
        issuer_from_metadata
      elsif @sp_yaml
        issuer_from_yaml
      end
    end

    def issuer_from_yaml
      parsed_sp_yaml["issuer"]
    end

    def issuer_from_metadata
      entity_descriptor_element = sp_metadata_doc.elements[ENTITY_DESCRIPTOR_PATH]
      entity_descriptor_element.attribute('entityID').value
    end

    def idp_cert_fingerprint_from_metadata
      base64_cert = idp_metadata_doc.elements[X509_CERT_PATH].text
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)
      fingerprint = Digest::SHA1.hexdigest(cert.to_der)
    end

    def idp_sso_target_url_from_metadata
      sso_service_element = idp_metadata_doc.elements[SSO_ELEMENT_PATH]
      sso_service_element.attribute('Location').value
    end
    
  end
end
