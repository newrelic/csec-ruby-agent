require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/kernel/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestKernel < Minitest::Test
                @@file_name = $test_path + "/resources/sample_file.txt"
                @@temp_file = $test_path + "/resources/tmp.txt"
                @@case_type = "SYSTEM_COMMAND"
                @@args = [@@file_name]
                @@event_category = nil
                def test_require
                   #out = require 'temp_module'
                end
                
                def test_system
                    $event_list.clear()
                    cmd = "pwd"
                    out = system(cmd)
                    assert_equal true, out
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end
                
                def test_backtick
                    $event_list.clear()
                    cmd = "touch #{@@temp_file}"
                    `#{cmd}` 
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
        
                    is_file_created = File.exist?(@@temp_file)
                    assert_equal true, is_file_created
                    File.delete(@@temp_file) if is_file_created
                end

                def test_delimiter
                    $event_list.clear()
                    cmd = "touch #{@@temp_file}"
                    @output = %x(#{cmd})
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
        
                    is_file_created = File.exist?(@@temp_file)
                    assert_equal true, is_file_created
                    File.delete(@@temp_file) if is_file_created
                end

                def test_delimiter2
                    $event_list.clear()
                    cmd = "touch #{@@temp_file}"
                    @output = %x`#{cmd}`
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
        
                    is_file_created = File.exist?(@@temp_file)
                    assert_equal true, is_file_created
                    File.delete(@@temp_file) if is_file_created
                end

                def test_spawn
                    $event_list.clear()
                    cmd = "touch #{@@temp_file}" 
                    spawn("#{cmd}")
                    sleep 0.01
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
        
                    is_file_created = File.exist?(@@temp_file)
                    assert_equal true, is_file_created
                    File.delete(@@temp_file) if is_file_created
                end
                
                def test_fork_exec 
                    $event_list.clear()
                    #TODO Not hooked
                    cmd = "touch #{@@temp_file}"
                    fork{exec("#{cmd}")}
                    sleep 0.01
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
        
                    is_file_created = File.exist?(@@temp_file)
                    assert_equal true, is_file_created
                    File.delete(@@temp_file) if is_file_created
                end
                
                def test_open
                    $event_list.clear()
                    cmd = "touch #{@@temp_file}"
                    open("\|#{cmd}").read
                    args = ['|' + cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
        
                    is_file_created = File.exist?(@@temp_file)
                    assert_equal true, is_file_created
                    File.delete(@@temp_file) if is_file_created
                end

            end
        end
    end
end
  