module Onelogin::Saml
  class Settings
    attr_accessor :assertion_consumer_service_url
    attr_accessor :issuer
    attr_accessor :sp_name_qualifier
    attr_accessor :idp_sso_target_url
    attr_accessor :idp_cert_fingerprint
    attr_accessor :name_identifier_format
    attr_accessor :private_key
    attr_accessor :private_key_password
  end
end
