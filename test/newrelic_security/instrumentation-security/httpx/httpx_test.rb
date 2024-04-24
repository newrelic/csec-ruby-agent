require 'httpx'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/httpx/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestHTTPX < Minitest::Test

                def test_get
                    $event_list.clear()
                    url = "http://www.google.com"
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil, :Body=>"", :Headers=>{}}]
                    response = HTTPX.get(url)
                    @output = response.status
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_get_ssl
                    $event_list.clear()
                    url = "https://www.google.com"
                    args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>"", :Headers=>{}}]
                    response = HTTPX.get(url)
                    @output = response.status
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_post_json
                    $event_list.clear()
                    url = "http://localhost:9291/books"
                    args = [{:Method=>"POST", :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books", :path=>"/books", :query=>nil, :Body=>"{\"title\":\"New\",\"author\":\"New Author\"}", :Headers=>{}}]
                    response = HTTPX.post(url, :json => {"title"=>"New","author"=>"New Author"})
                    @output = response.status
                    assert_equal 201, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_put_json
                    $event_list.clear()
                    url = "http://localhost:9291/books/1"
                    args = [{:Method=>"PUT", :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/books/1", :query=>nil, :Body=>"{\"title\":\"Update Book\",\"author\":\"Update Author\"}", :Headers=>{}}]
                    response = HTTPX.put(url, :json => {"title"=>"Update Book","author"=>"Update Author"})
                    @output = response.status
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_delete_json
                    $event_list.clear()
                    url = "http://localhost:9291/books/1"
                    args = [{:Method=>"DELETE", :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/books/1", :query=>nil, :Body=>"", :Headers=>{}}]
                    response = HTTPX.delete(url)
                    @output = response.status
                    assert_equal 204, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

            end
        end
    end
end
  