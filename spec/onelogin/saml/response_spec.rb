require 'spec_helper'
require 'base64'
require 'logger'

describe Onelogin::Saml::Response do
  let(:raw_saml) { File.open(File.dirname(__FILE__) + '/../../fixtures/saml-assertion-with-2-attributes.xml').read }

  let(:encrypted_saml) {File.open(File.dirname(__FILE__) + '/../../fixtures/saml-encrypted-assertion.xml').read }

  let(:settings) do
    settings = Onelogin::Saml::Settings.new
    
    settings.assertion_consumer_service_url   = "http://localhost:3000/auth/authenticate"
    settings.issuer                           = "saml-example" # the name of your application
    settings.idp_sso_target_url               = "http://dev.awesomesauce.com:8080/opensso/SSOPOST/metaAlias/idp"
    settings.idp_cert_fingerprint             = "def18dbed547cdf3d52b627f41637c443045fe33"
    settings.name_identifier_format           = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    File.open(File.dirname(__FILE__) + '/../../fixtures/ca.key') do |file|
      settings.private_key = file.read
    end
    settings.private_key_password = "ruby-saml"
    
    settings
  end

  let(:response) do
    response = Onelogin::Saml::Response.new(Base64.encode64(raw_saml))
    response.settings = settings
    #response.logger = Logger.new(STDOUT) # add this line for debugging
    response
  end

  let(:encrypted_response) do
    response = Onelogin::Saml::Response.new(Base64.encode64(encrypted_saml))
    response.settings = settings
    response
  end
  
  describe "name_id" do
    it "should pull the name id from authentication response" do
      response.name_id.should == "alex.redington@thinkrelevance.com"
    end

    it "should pull the name_id from encrypted responses correctly" do
      encrypted_response.name_id.should == "demo@example.com"
    end
  end

  describe "attributes" do 
    it "should pull attributes from authentication responses" do
      response.attributes["uuid"].should == "3c678d50-c357-012d-1a87-0017f2dcb387"
      response.attributes["name"].should == "happy"
    end
    
    it "should expose attributes directly on the response object" do
      response["uuid"].should == "3c678d50-c357-012d-1a87-0017f2dcb387"
    end

    it "should parse attributes out of encrypted responses correctly" do
      encrypted_response.attributes["uuid"].should == "3c678d50-c357-012d-1a87-0017f2dcb387"
      encrypted_response["name"].should == "happy"
    end
  end

  describe "valid?" do
    it "should validate the document successfully when attributes are present" do
      response.should be_valid
    end

    it "should validate an encrypted document successfully" do
      encrypted_response.should be_valid
    end

    it "should be able to call validate twice" do
      pending("make this test pass by not changing DOM in validation method") do
        response.should be_valid
        response.should be_valid
      end
    end
  end
  
  describe "encrypted?" do
    it "should return false if the response was NOT encrypted" do
      response.should_not be_encrypted
    end

    it "should return true if the response was encrypted" do
      encrypted_response.should be_encrypted
    end
  end
end
