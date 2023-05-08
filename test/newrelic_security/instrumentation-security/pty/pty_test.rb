require 'pty'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/pty/instrumentation'

module NewRelic::Security
  module Test
    module Instrumentation
      class TestPTY < Minitest::Test
        @@temp_file = $test_path + "/resources/tmp.txt"
        @@case_type = "SYSTEM_COMMAND"
        @@event_category = nil
        
        def test_spawn
          $event_list.clear()
          cmd = "touch #{@@temp_file}"
          args = [cmd]
          @output = PTY.spawn("#{cmd}")
          #puts @output
          expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
          assert_equal 1, $event_list.length
          assert_equal expected_event.caseType, $event_list[0].caseType
          assert_equal expected_event.parameters, $event_list[0].parameters
          assert_nil expected_event.eventCategory, $event_list[0].eventCategory
          File.delete(@@temp_file) if File.exist?(@@temp_file)
        end

        def test_getpty
          $event_list.clear()
          cmd = "touch #{@@temp_file}"
          args = [cmd]
          PTY::getpty("#{cmd}") do |reader, writer, pid|
            while true
              begin
                puts reader.readline
              rescue
                break
              end
            end
            @output = pid.to_s
          end
          #puts @output
          expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
          assert_equal 1, $event_list.length
          assert_equal expected_event.caseType, $event_list[0].caseType
          assert_equal expected_event.parameters, $event_list[0].parameters
          assert_nil expected_event.eventCategory, $event_list[0].eventCategory
          File.delete(@@temp_file) if File.exist?(@@temp_file)
        end
      end
    end
  end
end
  