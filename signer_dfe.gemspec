# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'signer_dfe/version'

Gem::Specification.new do |gem|
  gem.name          = "signer_dfe"
  gem.version       = SignerDfe::VERSION
  gem.authors       = ["Diogo Santinon"]
  gem.email         = ["diogo@softpagina.com.br"]
  gem.description   = %q{Sign XML of DFe with certificate and private key to .pem, and get information in the certificate. Gem based of signer}
  gem.summary       = %q{Gem make to DFe system of Brazil}
  gem.homepage      = "http://www.taxweb.com.br"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency('nokogiri')

  gem.add_development_dependency('rspec')
  gem.add_development_dependency('guard-rspec')
end
