require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/kernel/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestKernel < Minitest::Test
                TEMP_FILE = TEST_PATH + "/resources/tmp.txt"
                # def test_require
                #    #out = require 'temp_module'
                # end

                def setup
                    $event_list.clear()
                end
                
                def test_system
                    cmd = "pwd"
                    out = system(cmd)
                    assert_equal true, out
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
                
                def test_backtick
                    skip("Skipping for ruby 2.4.10 && instrumentation method chain") if RUBY_VERSION == '2.4.10' && ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == 'chain'
                    cmd = "touch #{TEMP_FILE}"
                    `#{cmd}` 
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
        
                    is_file_created = File.exist?(TEMP_FILE)
                    assert_equal true, is_file_created
                    File.delete(TEMP_FILE) if is_file_created
                end

                def test_delimiter
                    skip("Skipping for ruby 2.4.10 && instrumentation method chain") if RUBY_VERSION == '2.4.10' && ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == 'chain'
                    cmd = "touch #{TEMP_FILE}"
                    @output = %x(#{cmd})
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
        
                    is_file_created = File.exist?(TEMP_FILE)
                    assert_equal true, is_file_created
                    File.delete(TEMP_FILE) if is_file_created
                end

                def test_delimiter2
                    skip("Skipping for ruby 2.4.10 && instrumentation method chain") if RUBY_VERSION == '2.4.10' && ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == 'chain'
                    cmd = "touch #{TEMP_FILE}"
                    @output = %x`#{cmd}`
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
        
                    is_file_created = File.exist?(TEMP_FILE)
                    assert_equal true, is_file_created
                    File.delete(TEMP_FILE) if is_file_created
                end

                def test_spawn
                    cmd = "touch #{TEMP_FILE}"
                    spawn("#{cmd}")
                    sleep 0.01
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
        
                    is_file_created = File.exist?(TEMP_FILE)
                    assert_equal true, is_file_created
                    File.delete(TEMP_FILE) if is_file_created
                end
                
                # def test_fork_exec 
                #     #TODO Not hooked
                #     cmd = "touch #{TEMP_FILE}"
                #     fork{exec("#{cmd}")}
                #     sleep 0.01
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, [cmd], nil)
                #     assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_nil $event_list[0].eventCategory
        
                #     is_file_created = File.exist?(TEMP_FILE)
                #     assert_equal true, is_file_created
                #     File.delete(TEMP_FILE) if is_file_created
                # end
                
                def test_open
                    cmd = "touch #{TEMP_FILE}"
                    open("\|#{cmd}").read
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, ['|' + cmd], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SYSTEM_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
        
                    is_file_created = File.exist?(TEMP_FILE)
                    assert_equal true, is_file_created
                    File.delete(TEMP_FILE) if is_file_created
                end

                def teardown
                    $event_list.clear()
                end

            end
        end
    end
end
  