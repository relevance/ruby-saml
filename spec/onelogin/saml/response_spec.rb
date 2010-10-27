require 'spec_helper'
require 'base64'

describe Onelogin::Saml::Response do
  it "should pull attributes from authentication responses" do
    raw_saml = File.open(File.dirname(__FILE__) + '/../../fixtures/openam-assertion.saml').read
    response = Onelogin::Saml::Response.new(Base64.encode64(raw_saml))
    response.attributes["uuid"].should == "some-uuid"
    #response["uuid"].should == "some-uuid"    
  end
end
