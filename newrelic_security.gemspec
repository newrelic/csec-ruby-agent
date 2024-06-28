lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require_relative 'lib/newrelic_security/version'

Gem::Specification.new do |spec|
  spec.name          = 'newrelic_security'
  spec.version       = NewRelic::Security::VERSION
  spec.authors       = ['Prateek Sen']
  spec.licenses      = ['New Relic Pre-Release Software Notice']
  spec.email         = ['support@newrelic.com']

  spec.summary       = %q{Extension for newrelic_rpm with security feature}
  spec.description   = %q{New Relic is a performance management system, developed by New Relic,
    Inc (http://www.newrelic.com). This gem is an extension for newrelic_rpm with security feature, hosted on
    https://github.com/newrelic/csec-ruby-agent/}
  spec.homepage      = 'https://github.com/newrelic/csec-ruby-agent'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.4.0')
  spec.required_rubygems_version = Gem::Requirement.new('> 1.3.1') if spec.respond_to?(:required_rubygems_version=)

  spec.metadata = {
    'bug_tracker_uri' => 'https://github.com/newrelic/csec-ruby-agent/issues',
    'changelog_uri' => 'https://github.com/newrelic/csec-ruby-agent/blob/main/CHANGELOG.md',
    'documentation_uri' => 'https://docs.newrelic.com/docs/iast/introduction/',
    'source_code_uri' => 'https://github.com/newrelic/csec-ruby-agent',
    'homepage_uri' => 'https://github.com/newrelic/csec-ruby-agent'
  }
  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }.push(`git ls-files -z --others`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) } )
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.extra_rdoc_files = [
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'CONTRIBUTING.md'
  ]
  spec.require_paths = ['lib']

  spec.add_development_dependency 'minitest', "#{RUBY_VERSION >= '2.7.0' ? '~> 5.18' : '4.7.5'}"

  spec.add_development_dependency 'rubocop', "#{RUBY_VERSION < '2.6.0' ? '< 1.49.0' : '~> 1.49.0'}"
  spec.add_development_dependency 'rubocop-minitest', '~> 0.29' if RUBY_VERSION >= '2.6.0'
  spec.add_development_dependency 'rubocop-rake', '~> 0.6' if RUBY_VERSION >= '2.5.0'
  spec.add_development_dependency 'simplecov', '~> 0.22' if RUBY_VERSION >= '2.5.0'

end
