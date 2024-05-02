require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestIO < Minitest::Test
                FILE_NAME = TEST_PATH + "/resources/sample_file.txt"
                FILE2_NAME = TEST_PATH + "/resources/sample_file2.txt"
                TEMP_FILE = TEST_PATH + "/resources/tmp.txt"

                def setup
                    $event_list.clear()
                end

                def test_open
                    file_fd = IO.sysopen(FILE_NAME,"r")
                    file = IO.open(file_fd, 'r')
                    file.close
                    
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    # puts $event_list[0].caseType, $event_list[0].eventCategory, $event_list[0].parameters
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters  
                end
                
                def test_sysopen
                    file_fd = IO.sysopen(FILE_NAME, "r")
                    file = IO.new(file_fd, "r")
                    output = file.read
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters  
                end

                def test_read
                    output = IO.read(FILE_NAME)
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters
                end

                def test_read_arg1
                    output = IO.read(FILE_NAME, 21)
                    assert_equal "This is a sample text", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    #puts $event_list[0].caseType, $event_list[0].eventCategory, $event_list[0].parameters
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_read_arg2
                    output = File.read(FILE_NAME, 11, 10)
                    assert_equal "sample text", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_read_mode
                    output = File.read(FILE_NAME, mode: "r")
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_readlines
                    output = IO.readlines(FILE_NAME)
                    assert_equal "This is a sample text file", output[0]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_readlines_arg
                    output = IO.readlines(FILE2_NAME, chomp: true)
                    #output = IO.readlines(FILE2_NAME)
                    assert_equal "First line", output[0]
                    args = [FILE2_NAME]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_binread
                    output = IO.binread(FILE_NAME)
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_binread_arg1   
                    output = IO.binread(FILE_NAME, 21)
                    assert_equal "This is a sample text", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_binread_arg2    
                    output = File.binread(FILE_NAME, 11, 10)
                    assert_equal "sample text", output          
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_new_read 
                    file_fd = IO.sysopen(FILE_NAME,"r")
                    file = IO.new(file_fd,"r")
                    output = file.read
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters
                end

                def test_new_write 
                    file_fd = IO.sysopen(TEMP_FILE, "w")
                    file = IO.new(file_fd,"w")
                    file.puts "This is a temp text file"
                    file.close
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters
                    output = IO.read(TEMP_FILE)
                    assert_equal "This is a temp text file\n", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_new_write_utf 
                    file_fd = IO.sysopen(TEMP_FILE, "w")
                    file = io = IO.new(file_fd, mode: 'w:UTF-16LE', cr_newline: true)
                    file.puts "Temp file"
                    file.close
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters
                    # output = IO.read(TEMP_FILE)
                    # assert_equal "This is a temp text file\n", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_new_write_external_encoding 
                    file_fd = IO.sysopen(TEMP_FILE, "w")
                    file = IO.new(file_fd, mode: 'w', cr_newline: true, external_encoding: Encoding::UTF_16LE)
                    file.puts "Temp file"
                    file.close
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # TODO: update parameter when have http_context 
                    # assert_equal expected_event.parameters, $event_list[0].parameters
                    # output = IO.read(TEMP_FILE)
                    # assert_equal "This is a temp text file\n", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_foreach 
                    IO.foreach(FILE_NAME, "r") {|x| assert_equal x, "This is a sample text file"}
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, [FILE_NAME], READ)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_write
                    IO.write(TEMP_FILE, "Temp file")
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(TEMP_FILE)
                    assert_equal "Temp file", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_write_arg
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                    $event_list.clear()
                    IO.write(TEMP_FILE, "Temp file", 0)
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(TEMP_FILE)
                    assert_equal "Temp file", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_binwrite
                    IO.binwrite(TEMP_FILE, "Temp file")
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(TEMP_FILE)
                    assert_equal "Temp file", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_binwrite_arg
                    IO.binwrite(TEMP_FILE, "Temp file", 0)
                    args = [TEMP_FILE]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(FILE_OPERATION, args, WRITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(FILE_OPERATION)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(TEMP_FILE)
                    assert_equal "Temp file", output
                    File.delete(TEMP_FILE) if File.exist?(TEMP_FILE)
                end

                def test_popen
                    current_path = __dir__
                    cmd = "ls " + current_path
                    f = IO.popen(cmd)
                    output = f.read
                    #puts output
                    f.close
                    assert_equal "io_test.rb\n", output
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SYSTEM_COMMAND, args, nil)
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
  