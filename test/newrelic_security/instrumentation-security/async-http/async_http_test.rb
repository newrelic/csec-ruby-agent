require 'async'
require 'async/http/internet'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/async-http/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestAsyncHTTP < Minitest::Test

                def test_get
                    $event_list.clear()
                    url = "http://www.google.com"
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com/search?q=test", :path=>"/search", :query=>"q=test", :Body=>"", :Headers=>{"accept"=>"application/json"}}]
                    response = nil
                    Async do
                        internet = Async::HTTP::Internet.new
                        headers = [['accept', 'application/json']]
                        response = internet.get "http://www.google.com/search?q=test", headers
                        response.read
                    ensure
                        internet.close
                    end
                    assert_equal 200, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_get_ssl
                    $event_list.clear()
                    url = "http://www.google.com"
                    args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com/search?q=test", :path=>"/search", :query=>"q=test", :Body=>"", :Headers=>{"accept"=>"application/json"}}]
                    response = nil
                    Async do
                        internet = Async::HTTP::Internet.new
                        headers = [['accept', 'application/json']]
                        response = internet.get "https://www.google.com/search?q=test", headers
                        response.read
                    ensure
                        internet.close
                    end
                    assert_equal 200, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_post_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/create"
                    args = [{:Method=>"POST", :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/create", :path=>"/api/v1/create", :query=>nil, :Body=>"{\"name\":\"testuser\",\"salary\":\"123\",\"age\":\"23\"}", :Headers=>{"Content-Type"=>"application/json"}}]
                    data = {"name" => "testuser", "salary" => "123", "age" => "23"}
                    response = nil
                    Async do
                        internet = Async::HTTP::Internet.new
                        headers = [['Content-Type', 'application/json']]
                        body = [JSON.dump(data)]
                        response = internet.post url, headers, body
                        response.read
                    ensure
                        internet.close
                    end
                    assert_equal 200, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_put_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/update/2"
                    args = [{:Method=>"PUT", :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/update/2", :path=>"/api/v1/update/2", :query=>nil, :Body=>"{\"name\":\"testuser\",\"salary\":\"123\",\"age\":\"23\"}", :Headers=>{"Content-Type"=>"application/json"}}]
                    data = {"name" => "testuser", "salary" => "123", "age" => "23"}
                    response = nil
                    Async do
                        internet = Async::HTTP::Internet.new
                        headers = [['Content-Type', 'application/json']]
                        body = [JSON.dump(data)]
                        response = internet.put url, headers, body
                        response.read
                    ensure
                        internet.close
                    end
                    assert_equal 200, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_delete_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/delete/1"
                    args = [{:Method=>"DELETE", :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/delete/1", :path=>"/api/v1/delete/1", :query=>nil, :Body=>"", :Headers=>{"Content-Type"=>"application/json"}}]
                    response = nil
                    Async do
                        internet = Async::HTTP::Internet.new
                        headers = [['Content-Type', 'application/json']]
                        response = internet.delete url, headers
                        response.read
                    ensure
                        internet.close
                    end
                    assert_equal 200, response.status
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
  