require 'pty'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/pty/instrumentation'

module NewRelic::Security
  module Test
    module Instrumentation
      class TestPTY < Minitest::Test
        def setup
          $event_list.clear()
        end

        def test_spawn
          cmd = "date"
          PTY.spawn("#{cmd}")
          expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
          assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
          assert_equal expected_event.caseType, $event_list[0].caseType
          assert_equal expected_event.parameters, $event_list[0].parameters
          assert_nil $event_list[0].eventCategory
        end

        def test_getpty
          cmd = "date"
          PTY::getpty("#{cmd}") do |reader, writer, pid|
            begin
              reader.readline
            rescue
              break
            end
          end
          expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
          assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
          assert_equal expected_event.caseType, $event_list[0].caseType
          assert_equal expected_event.parameters, $event_list[0].parameters
          assert_nil $event_list[0].eventCategory
        end

        def teardown
          $event_list.clear()
        end

      end
    end
  end
end
