require 'http'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/httprb/instrumentation'
# require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNetHTTP < Minitest::Test

                def test_get
                    $event_list.clear()
                    url = "http://www.google.com"
                    args = [{:Method=>:get, :scheme=>:http, :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com/?foo=bar", :path=>"/", :query=>"foo=bar", :Body=>"", :Headers=>{"Accept-Encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "Accept"=>"*/*", "User-Agent"=>"Ruby", "Connection"=>"close"}}]
                    response = HTTP.headers(args[0][:Headers]).get(url, :params => {:foo => "bar"})
                    @output = response.code
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_get_ssl
                    $event_list.clear()
                    url = "https://www.google.com"
                    args = [{:Method=>:get, :scheme=>:https, :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com/?foo=bar", :path=>"/", :query=>"foo=bar", :Body=>"", :Headers=>{"Accept-Encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "Accept"=>"*/*", "User-Agent"=>"Ruby", "Connection"=>"close"}}]
                    response = HTTP.headers(args[0][:Headers]).get(url, :params => {:foo => "bar"})
                    @output = response.code
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_post_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/create"
                    args = [{:Method=>:post, :scheme=>:https, :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/create", :path=>"/api/v1/create", :query=>nil, :Body=>"{\"name\":\"testuser\",\"salary\":\"123\",\"age\":\"23\"}", :Headers=>{}}]
                    response = HTTP.post(url, :json => {:name => "testuser", :salary => "123",:age => "23"})
                    @output = response.code
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_put_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/update/2"
                    args = [{:Method=>:put, :scheme=>:https, :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/update/2", :path=>"/api/v1/update/2", :query=>nil, :Body=>"{\"name\":\"testuser\",\"salary\":\"123\",\"age\":\"23\"}", :Headers=>{}}]
                    response = HTTP.put(url, :json => {:name => "testuser", :salary => "123",:age => "23"})
                    @output = response.code
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_delete_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/delete/1"
                    args = [{:Method=>:delete, :scheme=>:https, :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/delete/1", :path=>"/api/v1/delete/1", :query=>nil, :Body=>"", :Headers=>{}}]
                    response = HTTP.delete(url)
                    @output = response.code
                    assert_equal 200, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

            end
        end
    end
end
  