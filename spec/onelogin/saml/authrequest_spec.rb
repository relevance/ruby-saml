require 'spec_helper'
require 'base64'

describe Onelogin::Saml::Authrequest do
  let(:settings) do
    settings = Onelogin::Saml::Settings.new
    
    settings.assertion_consumer_service_url   = "http://localhost:3000/auth/authenticate"
    settings.issuer                           = "saml-example" # the name of your application
    settings.idp_sso_target_url               = "http://dev.awesomesauce.com:8080/opensso/SSOPOST/metaAlias/idp"
    settings.idp_cert_fingerprint             = "def18dbed547cdf3d52b627f41637c443045fe33"
    settings.name_identifier_format           = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    
    settings
  end

  describe "create" do
    it "includes only the authentication request in the query string when no additional parameters are passed" do
      url = Onelogin::Saml::Authrequest.new.create(settings)
      url.should match(/\?SAMLRequest=[^&=]*$/)
    end
    
    it "includes additional, CGI-encoded parameters in the query string" do
      url = Onelogin::Saml::Authrequest.new.create(settings, "RelayState" => "/some/url", "foo" => "bar")
      url.should match(/RelayState=%2Fsome%2Furl/)
      url.should match(/foo=bar/)
    end

    it "includes additional parameters with non-string values" do
      url = Onelogin::Saml::Authrequest.new.create(settings, :number => 3.14159, :symbol => :some_symbol)
      url.should match(/number=3.14159/)
      url.should match(/symbol=some_symbol/)
    end
  end
end 
