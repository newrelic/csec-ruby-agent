require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/file/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestFile < Minitest::Test
                @@temp_file = $test_path + "/newrelic_security/../resources/tmp.txt"
                #@@temp_file = "/tmp/abc"
                @@case_type = "FILE_OPERATION"
                @@args = [@@temp_file]
                @@event_category = nil
                def test_delete
                    File.new(@@temp_file, "w") unless File.exist?(@@temp_file)
                    $event_list.clear()
                    out = File.delete(@@temp_file)
                    assert_equal 1, out
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_unlink
                    File.new(@@temp_file, "w") unless File.exist?(@@temp_file)
                    $event_list.clear()
                    out = File.unlink(@@temp_file)
                    assert_equal 1, out
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end
            end
        end
    end
end
  