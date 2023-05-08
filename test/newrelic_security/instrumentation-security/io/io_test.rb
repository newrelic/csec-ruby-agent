require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestIO < Minitest::Test
                @@file_name = $test_path + "/resources/sample_file.txt"
                @@file2_name = $test_path + "/resources/sample_file2.txt"
                @@temp_file = $test_path + "/resources/tmp.txt"
                @@case_type = "FILE_OPERATION"
                @@args = [@@file_name]
                @@event_category = nil

                def test_open
                    $event_list.clear()
                    file_fd = IO.sysopen(@@file_name,"r")
                    file = IO.open(file_fd, 'r')
                    file.close
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    #puts $event_list[0].caseType, $event_list[0].eventCategory, $event_list[0].parameters
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    assert_equal expected_event.parameters, $event_list[0].parameters
                end
                
                def test_sysopen
                    $event_list.clear()
                    file_fd = IO.sysopen(@@file_name, "r")
                    file = IO.new(file_fd, "r")
                    output = file.read
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_read
                    $event_list.clear()
                    output = IO.read(@@file_name)
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_read_arg1
                    $event_list.clear()
                    output = IO.read(@@file_name, 21)
                    assert_equal "This is a sample text", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_read_arg2
                    $event_list.clear()
                    output = File.read(@@file_name, 11, 10)
                    assert_equal "sample text", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_read_mode
                    $event_list.clear()
                    output = File.read(@@file_name, mode: "r")
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_readlines
                    $event_list.clear()
                    output = IO.readlines(@@file_name)
                    assert_equal "This is a sample text file", output[0]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_readlines_arg
                    $event_list.clear()
                    output = IO.readlines(@@file2_name, chomp: true)
                    #output = IO.readlines(@@file2_name)
                    assert_equal "First line", output[0]
                    args = [@@file2_name]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_binread
                    $event_list.clear()
                    output = IO.binread(@@file_name)
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_binread_arg1   
                    $event_list.clear() 
                    output = IO.binread(@@file_name, 21)
                    assert_equal "This is a sample text", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_binread_arg2    
                    $event_list.clear()
                    output = File.binread(@@file_name, 11, 10)
                    assert_equal "sample text", output          
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_new_read 
                    $event_list.clear()
                    file_fd = IO.sysopen(@@file_name,"r")
                    file = IO.new(file_fd,"r")
                    output = file.read
                    assert_equal "This is a sample text file", output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_new_write 
                    $event_list.clear()
                    file_fd = IO.sysopen(@@temp_file, "w")
                    file = IO.new(file_fd,"w")
                    file.puts "This is a temp text file"
                    file.close
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(@@temp_file)
                    assert_equal "This is a temp text file\n", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_new_write_utf 
                    $event_list.clear()
                    file_fd = IO.sysopen(@@temp_file, "w")
                    file = io = IO.new(file_fd, mode: 'w:UTF-16LE', cr_newline: true)
                    file.puts "Temp file"
                    file.close
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    # output = IO.read(@@temp_file)
                    # assert_equal "This is a temp text file\n", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_new_write_external_encoding 
                    $event_list.clear()
                    file_fd = IO.sysopen(@@temp_file, "w")
                    file = IO.new(file_fd, mode: 'w', cr_newline: true, external_encoding: Encoding::UTF_16LE)
                    file.puts "Temp file"
                    file.close
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    # output = IO.read(@@temp_file)
                    # assert_equal "This is a temp text file\n", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_foreach 
                    $event_list.clear()
                    output = IO.foreach(@@file_name, "r") {|x| assert_equal x, "This is a sample text file"}
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_write
                    $event_list.clear()
                    file = IO.write(@@temp_file, "Temp file")
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(@@temp_file)
                    assert_equal "Temp file", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_write_arg
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                    $event_list.clear()
                    file = IO.write(@@temp_file, "Temp file", 0)
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(@@temp_file)
                    assert_equal "Temp file", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_binwrite
                    $event_list.clear()
                    file = IO.binwrite(@@temp_file, "Temp file")
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(@@temp_file)
                    assert_equal "Temp file", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_binwrite_arg
                    $event_list.clear()
                    file = IO.binwrite(@@temp_file, "Temp file", 0)
                    args = [@@temp_file]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    output = IO.read(@@temp_file)
                    assert_equal "Temp file", output
                    File.delete(@@temp_file) if File.exist?(@@temp_file)
                end

                def test_popen
                    $event_list.clear()
                    current_path = __dir__
                    cmd = "ls " + current_path
                    f = IO.popen(cmd)
                    output = f.read
                    #puts output
                    f.close
                    assert_equal "io_test.rb\n", output
                    case_type = "SYSTEM_COMMAND"
                    args = [cmd]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

            end
        end
    end
end
  