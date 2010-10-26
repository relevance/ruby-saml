# -*- encoding: utf-8 -*-
# require File.expand_path("../lib/foo/version", __FILE__)

Gem::Specification.new do |s|
  s.name        = "ruby-saml"
  s.version = "0.0.4"
  # s.version     = Foo::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors = ["OneLogin LLC"]
  s.date = %q{2010-07-29}
  s.description = %q{SAML toolkit for Ruby}
  s.email = %q{support@onelogin.com}
  s.homepage = %q{http://github.com/onelogin/ruby-saml}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{SAML Ruby Tookit}

  s.required_rubygems_version = ">= 1.3.6"

  s.add_runtime_dependency "xmlcanonicalizer", ">= 0.1.0"
  s.add_runtime_dependency "uuid", "2.3.1"

  s.add_development_dependency "bundler", ">= 1.0.0"
  s.add_development_dependency "rspec", "2.0.0.rc"

  s.files        = `git ls-files`.split("\n")
  s.executables  = `git ls-files`.split("\n").map{|f| f =~ /^bin\/(.*)/ ? $1 : nil}.compact
  s.require_path = 'lib'
end
