require "base64"
require "uuid"
require "cgi"

module Onelogin::Saml
  class Authrequest
    attr_reader :transaction_id
    attr_writer :logger

    def initialize
      @transaction_id = UUID.new.generate
    end
    
    def create(settings, params = {})
      issue_instant = Onelogin::Saml::Authrequest.getTimestamp

      request = <<-EOF.gsub(/^\s*/, "")
        <AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{transaction_id}" Version="2.0" IssueInstant="#{issue_instant}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="#{settings.assertion_consumer_service_url}">
          <saml:Issuer>#{settings.issuer}</saml:Issuer>
          <NameIDPolicy Format="#{settings.name_identifier_format}" AllowCreate="true"/>
          <RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
            <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
            </saml:AuthnContextClassRef>
          </RequestedAuthnContext>
        </AuthnRequest>
        EOF

      @logger.debug("Raw SAML request: #{request}") unless @logger.nil?
      
      deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request    = Base64.encode64(deflated_request)  
      params["SAMLRequest"] = base64_request
      query_string = params.map {|key, value| "#{key}=#{CGI.escape(value)}"}.join("&")
      
      settings.idp_sso_target_url + "?#{query_string}"
    end
    
    private 
    
    def self.getTimestamp
      Time.new().strftime("%Y-%m-%dT%H:%M:%SZ")
    end
  end
end
