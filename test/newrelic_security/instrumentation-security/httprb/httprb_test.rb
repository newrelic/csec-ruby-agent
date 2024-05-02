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
                    args = [{:Method=>:get, :scheme=>:http, :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com/?foo=bar", :path=>"/", :query=>"foo=bar", :Body=>"", :Headers=>{"Accept-Encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "Accept"=>"*/*", "User-Agent"=>"Ruby", "Connection"=>"close"}}]
                    response = HTTP.headers(args[0][:Headers]).get(url, :params => {:foo => "bar"})
                    assert_equal 200, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_ssl
                    url = "https://www.google.com"
                    args = [{:Method=>:get, :scheme=>:https, :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com/?foo=bar", :path=>"/", :query=>"foo=bar", :Body=>"", :Headers=>{"Accept-Encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "Accept"=>"*/*", "User-Agent"=>"Ruby", "Connection"=>"close"}}]
                    response = HTTP.headers(args[0][:Headers]).get(url, :params => {:foo => "bar"})
                    assert_equal 200, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_post_json
                    url = "http://localhost:9291/books"
                    args = [{:Method=>:post, :scheme=>:http, :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books", :path=>"/books", :query=>nil, :Body=>"{\"title\":\"New\",\"author\":\"New Author\"}", :Headers=>{"Content-Type"=>"application/json"}}]
                    response = HTTP.headers(args[0][:Headers]).post(url, :json => {:title => "New", :author => "New Author"} )
                    assert_equal 201, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_put_json
                    url = "http://localhost:9291/books/1"
                    args = [{:Method=>:put, :scheme=>:http, :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/books/1", :query=>nil, :Body=>"{\"title\":\"Update Book\",\"author\":\"Update Author\"}", :Headers=>{"Content-Type"=>"application/json"}}]
                    response = HTTP.headers(args[0][:Headers]).put(url, :json => {:title => "Update Book", :author => "Update Author"})
                    assert_equal 200, response.code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_delete_json
                    url = "http://localhost:9291/books/1"
                    args = [{:Method=>:delete, :scheme=>:http, :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/books/1", :query=>nil, :Body=>"", :Headers=>{}}]
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
  