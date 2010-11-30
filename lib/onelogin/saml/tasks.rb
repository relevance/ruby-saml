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

          desc "Generate a Service Provider metadata file from ./config/saml/sp.yml"
          task :gen_sp_metadata do
            gen_sp_metadata
          end
        end
      end

      private

      def cert_from_filename(cert_file)
        if File.exists?(cert_file)
          cert_text = File.open(cert_file).read
          cert_text.gsub(/-----.* CERTIFICATE-----\n/,"")
        end
      end

      def missing_sp_yaml?
        unless File.exists?("./config/saml/sp.yml")
          puts "No such file: ./config/saml/sp.yml. Exiting."
          return true
        end
      end

      def incomplete_sp_yaml?(issuer, consumer_url, name_id_format, parsed_yaml)
        unless issuer && consumer_url && name_id_format
          needed_keys = ["issuer", "consumer_url", "name_id_format"]
          puts "sp.yml does not include #{(needed_keys - parsed_yaml.keys).join(", ")}, correct before generating metadata"
          return true
        end
      end

      def render_sp_metadata(issuer, consumer_url, name_id_format, cert_text)
        name_id_format = name_id_format.instance_of?(Array) ? name_id_format : [name_id_format]
        template = File.open(File.expand_path("../sp-metadata.xml.erb",__FILE__)).read
        erb = ERB.new(template,0,"%<>>")
        erb.result(binding)
      end

      def gen_sp_metadata
        return if missing_sp_yaml?
        sp_yaml = File.open("./config/saml/sp.yml").read
        parsed_yaml = YAML::load(sp_yaml)
        issuer = parsed_yaml["issuer"]
        consumer_url = parsed_yaml["consumer_url"]
        name_id_format = parsed_yaml["name_id_format"]
        return if incomplete_sp_yaml?(issuer, consumer_url, name_id_format, parsed_yaml)
        cert_file = parsed_yaml["cert_file"]
        if cert_file
          cert_text = cert_from_filename(cert_file)
        end
        output = render_sp_metadata(issuer, consumer_url, name_id_format, cert_text)
        File.open("./config/saml/sp.xml","w") { |f| f.write output }
        puts "Wrote ./config/saml/sp.xml"
      end
      
      def gen_cert
        unless missing_sp_yaml?
          sp_yaml = File.open("./config/saml/sp.yml").read
          parsed_yaml = YAML::load(sp_yaml)
          issuer = parsed_yaml["issuer"]
        end
        issuer ||= "service-provider"
        mkdir_p './config/saml'
        system "openssl req -x509 -days 1001 -newkey rsa:1024 -nodes -keyout ./config/saml/sp.key -out ./config/saml/sp.cer -subj '/CN=#{issuer}'"
        # To specify certificate fields on the command line: "-subj '/C=US/ST=state/L=city/O=org name/OU=dept name/CN=common name/emailAddress=email'"
      end
      
    end
  end
end

Onelogin::Saml::SamlTask.new
