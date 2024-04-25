require 'httpclient'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/net_http/instrumentation'
require 'newrelic_security/instrumentation-security/httpclient/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestHTTPClient < Minitest::Test
                @@url = "https://www.google.com"
                @@case_type = "HTTP_REQUEST"
                @@event_category = nil
                
                def test_get_content
                    $event_list.clear()
                    url = "https://www.google.com"
                    client = HTTPClient.new
	                @output = client.get_content(url)
                    #puts @output
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_request
                    $event_list.clear()
                    url = "https://www.google.com"
                    client = HTTPClient.new
                    method = 'GET'
                    @output = client.request(method, url).code
                    assert_equal 200, @output 
                    args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_get
                    $event_list.clear()
                    url = "https://www.google.com"
                    client = HTTPClient.new
	                @output = client.get(url, :follow_redirect => true).code 
                    assert_equal 200, @output 
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_head
                    $event_list.clear()
                    url = "https://www.google.com"
                    client = HTTPClient.new
	                @output = client.head(url).code
                    assert_equal 200, @output 
                    args = [{:Method=>:head, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_async
                    $event_list.clear()
                    url = "https://www.google.com"
                    client = HTTPClient.new
                    str = ""
                    client.debug_dev = str
                    conn = client.get_async(url)
                    #puts conn.code
                    Thread.pass while !conn.finished?
                    @output = str
                    #puts @output
                    #assert_equal 200, @output 
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                # def test_uri_open
                #     # URI.open test
                #     $event_list.clear()
                #     url = "https://www.google.com"
                #     #client = HTTPClient.new
	            #     @output = URI.open(url).read
                #     # puts @output
                #     case_type = "FILE_OPERATION"
                #     args = ["www.google.com"]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, @@event_category)
                #     assert_equal 3, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_nil expected_event.eventCategory, $event_list[0].eventCategory

                #     args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :path=>"/", :query=>nil, :URI=>"https://www.google.com:443/", :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby"}}]
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_nil expected_event2.eventCategory, $event_list[1].eventCategory
                # end
            end
        end
    end
end
  