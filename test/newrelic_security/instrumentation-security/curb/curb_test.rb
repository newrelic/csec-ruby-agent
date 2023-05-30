require 'curb'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/curb/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestCurb < Minitest::Test
                @@url = "https://www.google.com"
                @@case_type = "HTTP_REQUEST"
                @@event_category = nil
                @@args = [{:Method=>nil, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{}}]

                def test_curl 
                    $event_list.clear()
                    @output = Curl.get(@@url).url
                    assert_equal "https://www.google.com", @output  
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory  
                end

                def test_curl_multi_perform
                    $event_list.clear()
                    responses = {}
                    requests = ["https://www.google.com"]
                    m = Curl::Multi.new
                    requests.each do |url|
                        responses[url] = ""
                        c = Curl::Easy.new(url) do|curl|
                        curl.follow_location = true
                        
                        curl.on_body{ |data| responses[url] << data; data.size }
                        curl.on_success { @output = curl.code }
                        end
                        m.add(c)
                    end
                    m.perform do
                        #puts "idling... can do some work here"
                    end
                    assert_equal 200, @output  
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_curl_multi_get
                    $event_list.clear()
                    easy_options = {:follow_location => true}
                    multi_options = {}
                    Curl::Multi.get([@@url], easy_options, multi_options) do|easy|
                        # do something interesting with the easy response
                        @output= easy.code
                    end
                    assert_equal 200, @output  
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_curl_easy_perform
                    $event_list.clear()
                    response = Curl::Easy.perform(@@url)
                    @output = response.code
                    assert_equal 200, @output  
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
  