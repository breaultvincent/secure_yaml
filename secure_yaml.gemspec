# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "secure_yaml/version"

Gem::Specification.new do |s|
  s.name        = "secure_yaml_2"
  s.version     = SecureYaml::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Huw Lewis"]
  s.email       = ["huwtlewis@gmail.com"]
  s.homepage    = "https://github.com/qmg-hlewis/secure_yaml"
  s.summary     = %q{encryption protection for sensitive yaml properties}
  s.description = %q{encryption protection for sensitive yaml properties}

  s.rubyforge_project = "secure_yaml_2"

  s.files         = `git ls-files`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_development_dependency 'rspec', "~> 2.10"
  s.add_development_dependency 'rspec-mocks', "~> 2.10"
  s.add_development_dependency 'bundler', "~> 1.1"
  s.add_development_dependency 'rake', "~> 0.9"

end
