return if RUBY_ENGINE == 'jruby'
require 'curb'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/curb/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestCurb < Minitest::Test
                TEST_URL = "https://www.google.com"
                ARGS = ["https://www.google.com"]

                def setup
                    $event_list.clear()
                end

                def test_curl
                    @output = Curl.get(TEST_URL).url
                    assert_equal "https://www.google.com", @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, ARGS, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_curl_multi_perform
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
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, ARGS, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_curl_multi_get
                    easy_options = {:follow_location => true}
                    multi_options = {}
                    Curl::Multi.get([TEST_URL], easy_options, multi_options) do|easy|
                        # do something interesting with the easy response
                        @output= easy.code
                    end
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, ARGS, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_curl_easy_perform
                    response = Curl::Easy.perform(TEST_URL)
                    @output = response.code
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, ARGS, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
            end
        end
    end
end
