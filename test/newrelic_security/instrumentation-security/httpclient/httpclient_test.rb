require 'httpclient'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/httpclient/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestHTTPClient < Minitest::Test

                def setup
                    $event_list.clear()
                end
                
                def test_get_content
                    url = "https://www.google.com"
                    client = HTTPClient.new
	                @output = client.get_content(url)
                    #puts @output
                    args = ["https://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_request
                    url = "https://www.google.com"
                    client = HTTPClient.new
                    method = 'GET'
                    assert_equal 200, client.request(method, url).code
                    args = ["https://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get
                    url = "https://www.google.com"
                    client = HTTPClient.new
                    assert_equal 200, client.get(url, :follow_redirect => true).code
                    args = ["https://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_head
                    url = "https://www.google.com"
                    client = HTTPClient.new
                    assert_equal 200, client.head(url).code
                    args = ["https://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_async
                    # www.google.com's response never flips conn.finished? under HTTPClient's
                    # async path on this env (reproduces with plain httpclient, no instrumentation
                    # loaded); www.newrelic.com completes reliably, so use it here.
                    url = "https://www.newrelic.com"
                    client = HTTPClient.new
                    str = ""
                    client.debug_dev = str
                    conn = client.get_async(url)
                    #puts conn.code
                    # bounded wait: conn.finished? can otherwise spin forever (no timeout in httpclient's async API)
                    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
                    Thread.pass while !conn.finished? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
                    assert conn.finished?, "async HTTPClient request did not finish within 10s"
                    @output = str
                    #puts @output
                    #assert_equal 200, @output
                    args = ["https://www.newrelic.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                # def test_uri_open
                #     # URI.open test
                #     url = "https://www.google.com"
                #     #client = HTTPClient.new
	            #     @output = URI.open(url).read
                #     # puts @output
                #     case_type = "FILE_OPERATION"
                #     args = ["www.google.com"]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, nil)
                #     assert_equal 3, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_nil $event_list[0].eventCategory

                #     args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :path=>"/", :query=>nil, :URI=>"https://www.google.com:443/", :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby"}}]
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_nil expected_event2.eventCategory, $event_list[1].eventCategory
                # end
            end
        end
    end
end
  