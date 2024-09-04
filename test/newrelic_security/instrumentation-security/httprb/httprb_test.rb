require 'http'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/httprb/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestHTTP < Minitest::Test

                def setup
                    $event_list.clear()
                end

                def test_get
                    url = "http://www.google.com"
                    args = ["http://www.google.com"]
                    response = HTTP.headers({"Accept-Encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "Accept"=>"*/*", "User-Agent"=>"Ruby", "Connection"=>"close"}).get(url, :params => {:foo => "bar"})
                    assert_equal 200, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_ssl
                    url = "https://www.google.com"
                    args = ["http://www.google.com"]
                    response = HTTP.headers({"Accept-Encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "Accept"=>"*/*", "User-Agent"=>"Ruby", "Connection"=>"close"}).get(url, :params => {:foo => "bar"})
                    assert_equal 200, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_post_json
                    url = "http://localhost:9291/books"
                    args = ["http://localhost:9291/books"]
                    response = HTTP.headers({"Content-Type"=>"application/json"}).post(url, :json => {:title => "New", :author => "New Author"})
                    assert_equal 201, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_put_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    response = HTTP.headers({"Content-Type"=>"application/json"}).put(url, :json => {:title => "Update Book", :author => "Update Author"})
                    assert_equal 200, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_delete_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    response = HTTP.delete(url)
                    assert_equal 204, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

            end
        end
    end
end
  