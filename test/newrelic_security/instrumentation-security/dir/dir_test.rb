require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/dir/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestDir < Minitest::Test
                @@temp_dir = $test_path + "/resources/tmp"
                @@case_type = "FILE_OPERATION"
                @@args = [@@temp_dir]
                @@event_category = nil
                def test_mkdir_rmdir
                    # mkdir test
                    $event_list.clear()
                    output = Dir.mkdir(@@temp_dir)
                    assert_equal 0, output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    
                    # rmdir test
                    $event_list.clear()
                    output = Dir.rmdir(@@temp_dir)
                    assert_equal 0, output
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_unlink
                    # unlink test
                    $event_list.clear()
                    Dir.mkdir(@@temp_dir)
                    output = Dir.unlink(@@temp_dir)
                    assert_equal 0, output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end
            end
        end
    end
end
  