# test setup
# Define Log level for logging
ENV['NR_CSEC_LOG_LEVEL'] = 'INFO'
# Define instrumentation method 
ENV['NR_CSEC_INSTRUMENTATION_METHOD'] = 'prepend'

$: << File.expand_path('../../lib', __FILE__)
$: << File.expand_path('../../test', __FILE__)
$:.uniq!

require_relative 'simplecov_test_helper'
require 'rubygems'
require 'rake'

require 'minitest/autorun'
require 'minitest/pride' unless ENV['CI']

# Define test helper file path
$test_path = __dir__
# Declare event list
$event_list = []

# We can speed things up in tests that don't need to load rails.
# You can also run the tests in a mode without rails.

# Loading Security Agent  
puts "Running tests in Security standalone mode"
# For now, Can't initialize full security agent, because NR agent is not running.
# require 'newrelic_security'
require 'newrelic_security/version.rb'
require 'newrelic_security/agent/logging/init_logger'
require 'newrelic_security/agent/logging/logger'
require 'newrelic_security/agent/configuration/manager'
require 'newrelic_security/agent/agent'
require 'newrelic_security/agent/utils/agent_utils'
require 'newrelic_security/constants'

# loading helper files
Dir[File.expand_path('../helpers/*', __FILE__)].each { |f| require f }

# Create Agent instance
module NewRelic::Security
  module Agent  
    @agent = NewRelic::Security::Agent::Agent.new
  end
end

NewRelic::Security::Agent::Control::HTTPContext.clear_context