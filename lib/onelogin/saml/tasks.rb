require 'rake'
require 'rake/tasklib'
require 'webrick/ssl'
require 'erb'

module Onelogin
  module Saml
    class SamlTask < Rake::TaskLib
      
      def initialize
        namespace :saml do
          desc "Generate a self-signed certificate public/private key pair."
          task :gen_cert do
            gen_cert
          end

          desc "Generate a Service Provider metadata file from ./config/sp.yaml and ./config/saml_certs/saml.cer"
          task :gen_sp_metadata do
            gen_sp_metadata
          end
        end
      end

      private

      def gen_sp_metadata
        unless File.exists?("./config/sp.yml")
          puts "No such file: ./config/sp.yml. Exiting."
          return
        end
        sp_yaml = File.open("./config/sp.yml").read
        parsed_yaml = YAML::load(sp_yaml)
        issuer = parsed_yaml["issuer"]
        consumer_url = parsed_yaml["consumer_url"]
        name_id_format = parsed_yaml["name_id_format"]
        name_id_format = name_id_format.instance_of?(Array) ? name_id_format : [name_id_format]
        template = File.open(File.expand_path("../sp-metadata.xml.erb",__FILE__)).read
        erb = ERB.new(template)
        output = erb.result(binding)
        File.open("./config/sp.xml","w") { |f| f.write output }
      end

      def gen_cert
        #Expands to "/C=US/ST=Some-State/O=Internet Widgits Pty Ltd/emailAddress=demo@example.com"
        magic_der = "0f1\v0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\b\x13\nSome-State1!0\x1F\x06\x03U\x04\n\x13\x18Internet Widgits Pty Ltd1\x1F0\x1D\x06\t*\x86H\x86\xF7\r\x01\t\x01\x16\x10demo@example.com"
        
        puts "Generating keys..."
        cert, private_key = WEBrick::Utils.create_self_signed_cert(2048,magic_der,"Convenient fake certificate.")
        
        mkdir_p "./config/saml_certs"
        
        File.open("./config/saml_certs/saml.cer", "w") {|f| f.write(cert) }
        puts "Wrote public certificate to ./config/saml_certs/saml.cer"
        
        File.open("./config/saml_certs/saml.key", "w") {|f| f.write(private_key) }
        puts "Wrote private key to ./config/saml_certs/saml.key"
      end
    end
  end
end

Onelogin::Saml::SamlTask.new
