require 'nokogiri'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/nokogiri/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNokogiri < Minitest::Test
                def test_xpath
                    input = "'xyx'] or 1"
                    xml_file_path =  File.expand_path('../', __FILE__) + "/employees.xml"
                    f = File.open(xml_file_path)
                    $event_list.clear()
                    doc = Nokogiri::XML(f)
                    output = doc.xpath(".//employee[firstName[text()=#{input.to_s}]")
                    f.close
                    # data verify 
                    assert_equal "1", output[0].attr('id')
                    assert_equal "2", output[1].attr('id')
                    # event verify
                    args = [{:paths=>[".//employee[firstName[text()='xyx'] or 1]"], :variables=>nil}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(XPATH, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(XPATH)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
                
            end
        end
    end
end
  