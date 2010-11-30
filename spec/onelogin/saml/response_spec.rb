require 'spec_helper'
require 'base64'
require 'logger'
require 'time'
require 'timecop'

describe Onelogin::Saml::Response do

  def read_assertion_fixture(name)
    File.open(File.dirname(__FILE__) + "/../../fixtures/#{name}").read
  end

  def response_for_saml(saml)
    response = Onelogin::Saml::Response.new(Base64.encode64(saml))
    response.settings = settings
    response
  end
  
  let(:raw_saml) { read_assertion_fixture("saml-assertion-with-2-attributes.xml") }

  let(:encrypted_saml) { read_assertion_fixture("saml-encrypted-assertion.xml") }

  let(:busted_id_saml) { read_assertion_fixture("saml-assertion-with-busted-ids.xml") }

  let(:broken_digest_saml) { read_assertion_fixture("saml-assertion-with-broken-digest.xml") }

  let(:settings) do
    settings = Onelogin::Saml::Settings.new
    
    settings.assertion_consumer_service_url   = "http://localhost:3000/auth/authenticate"
    settings.issuer                           = "saml-example" # the name of your application
    settings.idp_sso_target_url               = "http://dev.awesomesauce.com:8080/opensso/SSOPOST/metaAlias/idp"
    settings.idp_cert_fingerprint             = "def18dbed547cdf3d52b627f41637c443045fe33"
    settings.name_identifier_format           = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    File.open(File.dirname(__FILE__) + '/../../fixtures/sp.key') do |file|
      settings.private_key = file.read
    end
    settings.private_key_password = "ruby-saml"
    
    settings
  end

  let(:response) do
    response_for_saml(raw_saml)
  end

  let(:encrypted_response) do
    response_for_saml(encrypted_saml)
  end

  let(:busted_id_response) do
    response_for_saml(busted_id_saml)
  end

  let (:broken_digest_response) do
    response_for_saml(broken_digest_saml)
  end

  let (:response_time_freeze) do
    Time.parse("October 28th, 2010 1:35pm UTC")
  end

  let(:encrypted_response_time_freeze) do
    Time.parse("November 1st, 2010 8:17pm UTC")
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
      Timecop.freeze(response_time_freeze) do
        response.should be_valid
      end
    end

    it "should validate an encrypted document successfully" do
      Timecop.freeze(encrypted_response_time_freeze) do
        encrypted_response.should be_valid
      end
    end

    it "should be able to call validate twice" do
      Timecop.freeze(response_time_freeze) do
        response.should be_valid
        response.should be_valid
      end
    end

    describe "with timestamps" do
      it "documents are NOT valid before their expiration dates" do
        Timecop.freeze(Time.parse("October 28th, 2010 1:20pm UTC")) do
          response.should_not be_valid
        end
      end
      
      it "documents are NOT valid after their expiration dates" do
        Timecop.freeze(Time.parse("October 28th, 2010 1:46pm UTC")) do
          response.should_not be_valid
        end
      end
      
      it "documents are valid only within their expiration dates" do
        Timecop.freeze(response_time_freeze) do
          response.should be_valid
        end
      end
      
    end

    describe "with transaction ids" do
      it "documents are valid if no transaction id is provided" do
        Timecop.freeze(response_time_freeze) do
          response.should be_valid
        end
      end

      it "documents are valid if a matching transaction id is provided" do
        Timecop.freeze(response_time_freeze) do
          response.expected_transaction_id = "294e5540-c4c6-012d-1a98-0017f2dcb387"
          response.should be_valid
        end
      end

      it "documents are NOT valid if the expected transaction id does not match the document's transaction id" do
        Timecop.freeze(response_time_freeze) do
          response.expected_transaction_id = "quux-zot-bar-foo-baz"
          response.should_not be_valid
        end
      end

      it "is NOT valid if the two transaction IDs in the document do NOT match" do
        Timecop.freeze(response_time_freeze) do
          busted_id_response.should_not be_valid
        end        
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

  describe "errors" do

    it "should return an empty hash if validation encountered no errors" do
      Timecop.freeze(response_time_freeze) do
        response.valid?.should == true
        response.errors.should == {}
      end
    end

    it "should log an error when the document has inconsistent InResponseTo ids" do
      Timecop.freeze(response_time_freeze) do
        busted_id_response.valid?.should == false
        busted_id_response.errors.should include(:base)
        busted_id_response.errors[:base].should == "samlp:AuthnRequest and saml:SubjectConfirmationData InResponseTo IDs do not match"
      end
    end

    it "should log an error when the actual and expected transaction_ids don't match" do
      Timecop.freeze(response_time_freeze) do
        response.expected_transaction_id = "quux-zot-bar-baz-foo"
        response.valid?.should == false
        response.errors.should include(:transaction_id)
        response.errors[:transaction_id].should == "saml:SubjectConfirmationData InResponseTo does not match expected_transaction_id"
      end
    end

    it "should log an error when the document is after it's expiration date" do
      Timecop.freeze(Time.parse("October 28th, 2010 1:46pm UTC")) do
        response.valid?.should == false
        response.errors.should include(:expiration_date)
        response.errors[:expiration_date].should == "the saml:Conditions NotOnOrAfter time has expired"
      end
    end

    it "should log an error when the document is before it's ripeness date" do
      Timecop.freeze(Time.parse("October 28th, 2010 1:24pm UTC")) do
        response.valid?.should == false
        response.errors.should include(:ripeness_date)
        response.errors[:ripeness_date].should == "the saml:Conditions NotBefore time has not yet passed"
      end
    end

    it "should log an error when the signing cert's hash does not match the fingerprint" do
      Timecop.freeze(response_time_freeze) do
        settings.idp_cert_fingerprint = "brokenidpcertfingerprint"
        response.settings = settings
        response.valid?.should == false
        response.errors.should include(:idp_cert_fingerprint)
        response.errors[:idp_cert_fingerprint].should == "the ds:X509Certificate's hash did not match the provided idp_cert_fingerprint"
      end
    end

    it "should log an error when the calculated and specified digest value do not match" do
      Timecop.freeze(response_time_freeze) do
        broken_digest_response.valid?.should == false
        broken_digest_response.errors.should include(:digest)
        broken_digest_response.errors[:digest].should == "the ds:DigestValue's digest did not match the calculated assertion's digest"
      end
    end

    it "should log an error when the specified signature does not match" do
      Timecop.freeze(response_time_freeze) do
        broken_digest_response.valid?.should == false
        broken_digest_response.errors.should include(:signature)
        broken_digest_response.errors[:signature].should == "the ds:Signature value could not validate the assertion when checked against the cert"
      end
    end

  end
  
end
