# Define Test environment
ENV['RAILS_ENV'] = 'test'
ENV['NO_RAILS'] = 'true'
# If this env set to False, Only Security Agent will be loaded.
ENV['NR'] = 'false'

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
if ENV['NR'] == 'false'
  puts "Running tests in Security standalone mode without Rails."
  # For now, Can't initialize complete security agent, because NR agent is not running.
  # require 'newrelic_security'
  require 'newrelic_security/version.rb'
  require 'newrelic_security/agent/logging/init_logger'
  require 'newrelic_security/agent/logging/logger'
  require 'newrelic_security/agent/configuration/manager'
  require 'newrelic_security/agent/agent'
  require 'newrelic_security/agent/utils/agent_utils'
  require 'newrelic_security/constants'
else
  begin
    # try loading NR and Security modules
    require 'newrelic_rpm'
    require 'newrelic_security'
    puts "Running in integrated security mode without Rails"
  rescue LoadError
    # if there was not a file at config/environment.rb fall back to running without it
    require 'newrelic_security'
    puts "Running in security standalone mode without Rails"
  end
end

# loading helper files
Dir[File.expand_path('../helpers/*', __FILE__)].each { |f| require f }

# Create Agent instance
module NewRelic::Security
  module Agent  
    @agent = NewRelic::Security::Agent::Agent.new
  end
end