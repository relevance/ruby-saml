require 'spec_helper'

describe Onelogin::Saml::Settings do
  
  let(:settings) do
    settings = Onelogin::Saml::Settings.new
  end

  describe "idp_metadata" do
    
    before(:each) do
      settings.idp_metadata = File.dirname(__FILE__) + "/../../fixtures/idp.xml"
    end
    
    it "pulls idp_sso_target_url from the idp metadata" do
      settings.idp_sso_target_url.should == "http://saml.example.com/login"
    end
    
    it "pulls idp_cert_fingerprint from the idp metadata" do
      settings.idp_cert_fingerprint.should == "def18dbed547cdf3d52b627f41637c443045fe33"
    end
  end

  describe "sp_metadata" do
    
    before(:each) do
      settings.sp_metadata = File.dirname(__FILE__) + "/../../fixtures/sp.xml"
    end

    it "pulls issuer from the sp metadata" do
      settings.issuer.should == "http://sp.example.com"
    end

    it "pulls assertion_consumer_service_url from the sp metadata" do
      settings.assertion_consumer_service_url.should == "http://sp.example.com/session"
    end

    it "defaults name_identifier_format from the sp metadata if unset" do
      settings.name_identifier_format.should == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    end

    it "overrides name_identifier_format with the explicitly set value if set" do
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      settings.sp_metadata = File.dirname(__FILE__) + "/../../fixtures/sp.xml"
      settings.name_identifier_format.should == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    end
        
  end

  describe "sp_yaml" do
    let(:private_key_path) { File.dirname(__FILE__) + "/../../fixtures/sp.key" }
    let(:private_key_text) { File.open(private_key_path) {|file| file.read }}

    before(:each) do
      settings.sp_yaml = File.dirname(__FILE__) + "/../../fixtures/sp.yml"
    end

    it "pulls issuer from the sp yaml" do
      settings.issuer.should == "http://sp.example.com"
    end
    
    it "pulls assertion_consumer_service_url from the sp yaml" do
      settings.assertion_consumer_service_url.should == "http://sp.example.com/session"
    end
    
    it "defaults name_identifier_format from the sp yaml if unset" do
      settings.name_identifier_format.should == "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    end
    
    it "overrides name_identifier_format with the explicitly set value if set" do
      settings.name_identifier_format = "some-explicit-value"
      settings.sp_metadata = File.dirname(__FILE__) + "/../../fixtures/sp.xml"
      settings.name_identifier_format.should == "some-explicit-value"
    end

    it "pulls private_key_password from the sp yaml if unset" do
      settings.private_key_password.should == "password_from_sp_yml"
    end

    it "pulls private_key from the sp yaml if unset" do
      settings.private_key.should == private_key_text
    end
  end

  describe "private_key_password" do
    it "returns nil if neither sp_yaml nor private_key_password are specified" do
      settings.private_key_password.should == nil
    end
  end
end
