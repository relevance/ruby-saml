require 'spec_helper'
require 'base64'

describe Onelogin::Saml::Response do
  let(:raw_saml) { File.open(File.dirname(__FILE__) + '/../../fixtures/openam-assertion.saml').read }
  let(:response) { Onelogin::Saml::Response.new(Base64.encode64(raw_saml)) } 

  it "should pull attributes from authentication responses" do
    response.attributes["uuid"].should == "3c678d50-c357-012d-1a87-0017f2dcb387"
  end

  it "should expose attributes directly on the response object" do
    response["uuid"].should == "3c678d50-c357-012d-1a87-0017f2dcb387"
  end

end
