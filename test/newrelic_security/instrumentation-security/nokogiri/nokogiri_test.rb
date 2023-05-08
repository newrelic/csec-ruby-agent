require 'nokogiri'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/nokogiri/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNokogiri < Minitest::Test

                def test_xpath_node
                    $event_list.clear()
                    input = "'xyx'] or 1"
                    employee_file_path =  File.expand_path('../', __FILE__) + "/employees.xml"
                    f = File.open(employee_file_path)
                    doc = Nokogiri::XML(f)
                    @output = doc.xpath(".//employee[firstName[text()=#{input.to_s}]")
                    #puts @output
                    case_type = "XPATH"
                    args = [{:paths=>[".//employee[firstName[text()='xyx'] or 1]"], :variables=>nil}]
                    event_category = nil
                    expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end

                # def test_xpath_nodeset
                # end
                
            end
        end
    end
end
  