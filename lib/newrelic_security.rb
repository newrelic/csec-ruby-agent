require "newrelic_security/version"

module NewRelic::Security
  class Error < StandardError; end
  require 'newrelic_security/agent' unless defined?(NewRelic::Security::Agent)
end
