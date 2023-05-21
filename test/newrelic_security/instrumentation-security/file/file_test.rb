require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/file/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestFile < Minitest::Test
                @@temp_dir = $test_path + "/resources/temp"
                @@temp_file = @@temp_dir + "/abc.txt"
                @@case_type = "FILE_INTEGRITY"
                @@args = [@@temp_file]
                @@event_category = nil
                
                def test_delete
                    Dir.mkdir(@@temp_dir) unless Dir.exist?(@@temp_dir)
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
                    Dir.mkdir(@@temp_dir) unless Dir.exist?(@@temp_dir)
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
  