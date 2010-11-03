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

    DS_NAMESPACE = {"ds"=>"http://www.w3.org/2000/09/xmldsig#"}

    def validate_fingerprint(idp_cert_fingerprint, logger = nil)
      debug("Received cert: #{cert}",logger)
      
      fingerprint = Digest::SHA1.hexdigest(cert.to_der)
      expected_fingerprint = idp_cert_fingerprint.gsub(":","").downcase
      valid = fingerprint == expected_fingerprint

      if valid
        debug("assertion fingerprint matched", logger)
      else
        debug("assertion did not match; fingerprint was #{fingerprint}, expected #{expected_fingerprint}",logger)
      end
      
      valid
    end

    def validate_digests(logger)
      doc = self.deep_clone
      sig_element = sig_element(doc)
      sig_element.remove

      REXML::XPath.each(sig_element, "//ds:Reference", DS_NAMESPACE) do | ref |
        uri = ref.attributes.get_attribute("URI").value
        debug("Digest URI: #{uri}",logger)

        hashed_element = REXML::XPath.first(doc, "//[@ID='#{uri[1,uri.size]}']")
        debug("Hashed element: #{hashed_element}",logger)

        canon_hashed_element = canonical_form(hashed_element)
        debug("Canonical hashed element: #{canon_hashed_element}",logger)

        hash = Digest::SHA1.digest(canon_hashed_element)
        digest_value = decode64_from_xpath(ref, "//ds:DigestValue")
        debug("calculated hash: #{hash}, expected_hash: #{digest_value}",logger)

        return false unless hash == digest_value        
      end
      
      true
    end

    def validate_signature(logger = nil)
      doc = self.deep_clone
      sig_element = sig_element(doc)
 
      signed_info_element = REXML::XPath.first(sig_element, "//ds:SignedInfo", DS_NAMESPACE)
      canonical_form = canonical_form(signed_info_element)

      signature = decode64_from_xpath(sig_element, "//ds:SignatureValue")
      cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canonical_form)
    end

    private

    def decode64_from_xpath(element, xpath)
      xpath_result = REXML::XPath.first(element, xpath, DS_NAMESPACE)
      Base64.decode64(xpath_result.text)
    end

    def cert(doc = self)
      base64_cert = doc.elements["//ds:X509Certificate"].text
      cert_text = Base64.decode64(base64_cert)
      OpenSSL::X509::Certificate.new(cert_text)
    end

    def canonical_form(element)
      canonicalizer = XML::Util::XmlCanonicalizer.new(false,true)
      canonicalizer.canonicalize(element)
    end

    def sig_element(document)
      REXML::XPath.first(document, "//ds:Signature", DS_NAMESPACE)
    end      
    
    def debug(message,logger)
      logger.debug(message) if logger
    end
   
  end
end
