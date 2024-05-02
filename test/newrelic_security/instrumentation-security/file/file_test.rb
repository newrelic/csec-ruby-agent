require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/file/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestFile < Minitest::Test
                TEMP_DIR = TEST_PATH + "/resources/temp"
                TEMP_FILE = TEMP_DIR + "/abc.txt"
                
                def test_delete
                    Dir.mkdir(TEMP_DIR) unless Dir.exist?(TEMP_DIR)
                    File.new(TEMP_FILE, "w") unless File.exist?(TEMP_FILE)
                    $event_list.clear()
                    out = File.delete(TEMP_FILE)
                    assert_equal 1, out
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_INTEGRITY, [TEMP_FILE], DELETE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_INTEGRITY)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_unlink
                    Dir.mkdir(TEMP_DIR) unless Dir.exist?(TEMP_DIR)
                    File.new(TEMP_FILE, "w") unless File.exist?(TEMP_FILE)
                    $event_list.clear()
                    out = File.unlink(TEMP_FILE)
                    assert_equal 1, out
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_INTEGRITY, [TEMP_FILE], DELETE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_INTEGRITY)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end
            end
        end
    end
end
  