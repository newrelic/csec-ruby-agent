require 'httpx'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/httpx/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestHTTPX < Minitest::Test

                def setup
                    $event_list.clear()
                end

                def test_get
                    url = "http://www.google.com"
                    args = ["http://www.google.com"]
                    response = HTTPX.get(url)
                    @output = response.status
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_ssl
                    url = "https://www.google.com"
                    args = ["https://www.google.com"]
                    response = HTTPX.get(url)
                    @output = response.status
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil $event_list[0].eventCategory
                end

                def test_post_json
                    url = "http://localhost:9291/books"
                    args = ["http://localhost:9291/books"]
                    response = HTTPX.post(url, :json => {"title"=>"New", "author"=>"New Author"})
                    @output = response.status
                    assert_equal 201, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil $event_list[0].eventCategory
                end

                def test_put_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    response = HTTPX.put(url, :json => {"title"=>"Update Book", "author"=>"Update Author"})
                    @output = response.status
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil $event_list[0].eventCategory
                end

                def test_delete_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    response = HTTPX.delete(url)
                    @output = response.status
                    assert_equal 204, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil $event_list[0].eventCategory
                end

            end
        end
    end
end
  