require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/dir/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestDir < Minitest::Test
                TMP_DIR = $test_path + "/resources/tmp"
                TEMP_DIR = $test_path + "/resources/temp"

                def test_mkdir_rmdir_file_operation
                    # mkdir test
                    FileUtils.remove_dir(TMP_DIR) if Dir.exist?(TMP_DIR)
                    $event_list.clear()
                    output = Dir.mkdir(TMP_DIR)
                    assert_equal 0, output
                    # event verify
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [TMP_DIR], WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    
                    # rmdir test
                    $event_list.clear()
                    output = Dir.rmdir(TMP_DIR)
                    assert_equal 0, output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [TMP_DIR], DELETE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_mkdir_rmdir_file_integrity
                    FileUtils.remove_dir(TEMP_DIR) if Dir.exist?(TEMP_DIR)
                    $event_list.clear()
                    
                    # mkdir test
                    output = Dir.mkdir(TEMP_DIR)
                    assert_equal 0, output
                    # event verify
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_INTEGRITY, [TEMP_DIR], WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_INTEGRITY)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    
                    # rmdir test
                    $event_list.clear()
                    output = Dir.rmdir(TEMP_DIR)
                    assert_equal 0, output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_INTEGRITY, [TEMP_DIR], DELETE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_INTEGRITY)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_unlink_file_operation
                    # unlink test
                    FileUtils.remove_dir(TMP_DIR) if Dir.exist?(TMP_DIR)
                    $event_list.clear()
                    Dir.mkdir(TMP_DIR)
                    output = Dir.unlink(TMP_DIR)
                    assert_equal 0, output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [TMP_DIR], DELETE)
                    assert_equal 2, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_equal expected_event.eventCategory, $event_list[1].eventCategory
                end

                def test_unlink_file_integrity
                    FileUtils.remove_dir(TEMP_DIR) if Dir.exist?(TEMP_DIR)
                    Dir.mkdir(TEMP_DIR)
                    $event_list.clear()
                    # unlink test
                    output = Dir.unlink(TEMP_DIR)
                    assert_equal 0, output
                    # event verify
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_INTEGRITY, [TEMP_DIR], DELETE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_INTEGRITY)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end
            end
        end
    end
end
  