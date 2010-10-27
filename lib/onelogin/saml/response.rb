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
      @document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].text
    end

    def attributes
      @document.saml_attributes
    end

    def [](key)
      self.attributes[key]
    end
  end
end
