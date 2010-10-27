# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
 
module XMLSecurity

  class SignedDocument < REXML::Document

    def validate (idp_cert_fingerprint, logger = nil)
      # get cert from response
      base64_cert             = self.elements["//ds:X509Certificate"].text
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      logger.debug("Received cert: #{cert}") if logger
      
      # check cert matches registered idp cert
      fingerprint             = Digest::SHA1.hexdigest(cert.to_der)
      expected_fingerprint = idp_cert_fingerprint.gsub(":","").downcase
      valid_flag              = fingerprint == expected_fingerprint

      unless valid_flag
        logger.error("Validating SAML assertion failed fingerprint check, assertion fingerprint was #{fingerprint}, expected #{expected_fingerprint}") if logger
        return false
      end
      
      validate_doc(base64_cert, logger)
    end

    def saml_attributes
      saml_attributes = {}
      
      each_saml_attribute(self,"//saml:AttributeStatement") do |statement_element|
        each_saml_attribute(statement_element, "./saml:Attribute") do |attribute_element|
          each_saml_attribute(attribute_element, "./saml:AttributeValue") do |value_element|
            attr_name = attribute_element.attributes["Name"]            
            saml_attributes[attr_name] = value_element.text
          end
        end
      end
      
      saml_attributes
    end

    private
    
    def each_saml_attribute(element, selector, &blk)
      REXML::XPath.each(element, selector, {"saml" => "urn:oasis:names:tc:SAML:2.0:assertion"},  &blk)
    end
    
    def validate_doc(base64_cert, logger)
      # validate references
      
      # remove signature node
      sig_element = REXML::XPath.first(self, "//ds:Signature", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})
      sig_element.remove
      logger.debug("Removed signature node.") if logger
      
      #check digests
      REXML::XPath.each(sig_element, "//ds:Reference", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}) do | ref |          
        
        uri                   = ref.attributes.get_attribute("URI").value
        logger.debug("Digest URI: #{uri}") if logger
        hashed_element        = REXML::XPath.first(self, "//[@ID='#{uri[1,uri.size]}']")
        logger.debug("Hashed element: #{hashed_element}") if logger
        canoner               = XML::Util::XmlCanonicalizer.new(false, true)
        begin
          canon_hashed_element  = canoner.canonicalize(hashed_element)
        rescue Exception => exception
          logger.debug("Exception raised trying to canonicalize the element. #{exception}, #{exception.backtrace}") if logger
        end
        logger.debug("Canonical hashed element: #{canon_hashed_element}") if logger
        hash                  = Base64.encode64(Digest::SHA1.digest(canon_hashed_element)).chomp
        digest_value          = REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}).text
        
        valid_flag            = hash == digest_value
        logger.debug("calculated hash: #{hash}, expected_hash: #{digest_value}") if logger
        logger.debug("Digest check for #{uri} passed: #{valid_flag}") if logger
        
        return valid_flag if !valid_flag
      end
 
      # verify signature
      canoner                 = XML::Util::XmlCanonicalizer.new(false, true)
      signed_info_element     = REXML::XPath.first(sig_element, "//ds:SignedInfo", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"})
      canon_string            = canoner.canonicalize(signed_info_element)

      base64_signature        = REXML::XPath.first(sig_element, "//ds:SignatureValue", {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}).text
      signature               = Base64.decode64(base64_signature)
      
      # get certificate object
      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)
      
      valid_flag              = cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canon_string)
        
      return valid_flag
    end
   
  end
end
