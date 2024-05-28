require_relative 'simplecov_test_helper'
require 'rubygems'
require 'rake'
require 'rack'
require 'rack/handler'
require 'minitest/autorun'
require 'minitest/pride' unless ENV['CI']

ENV['NR_CSEC_LOG_LEVEL'] = 'INFO'
# ENV['NR_CSEC_INSTRUMENTATION_METHOD'] = 'prepend' # No need to enable this prepend is already by default in loader

$: << File.expand_path('../../lib', __FILE__)
$: << File.expand_path('../../test', __FILE__)
$:.uniq!

require 'newrelic_security/version.rb'
require 'newrelic_security/agent/logging/init_logger'
require 'newrelic_security/agent/logging/logger'
require 'newrelic_security/agent/configuration/manager'
require 'newrelic_security/agent/agent'
require 'newrelic_security/agent/utils/agent_utils'
require 'newrelic_security/constants'
require 'helpers/agent_helper'
require 'helpers/config_helper'
require 'helpers/event_helper'
require 'helpers/init_helper'
require 'helpers/sample_server'
require 'helpers/database_helper'

# Create Agent instance
module NewRelic::Security
  module Test
    TEST_PATH = __dir__
    $event_list = [] #this variable stores the events created for the instrumented methods
  end

  module Agent  
    @agent = NewRelic::Security::Agent::Agent.new
    @sample_server = Thread.new { ::Rack::Server.start app: NewRelic::Security::Test::SampleServer, Port: 9291 }
  end
end
