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
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil, :Body=>"", :Headers=>{"user-agent"=>"httpx.rb/1.2.3", "accept"=>"*/*", "accept-encoding"=>"gzip, deflate"}}]
                    response = HTTPX.get(url)
                    @output = response.status
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
                    args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil, :Body=>"", :Headers=>{"user-agent"=>"httpx.rb/1.2.3", "accept"=>"*/*", "accept-encoding"=>"gzip, deflate"}}]
                    response = HTTPX.get(url)
                    @output = response.status
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
                    args = [{:Method=>"POST", :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/create", :path=>"/api/v1/create", :query=>nil, :Body=>"{\"name\":\"testuser\",\"salary\":\"123\",\"age\":\"23\"}", :Headers=>{"user-agent"=>"httpx.rb/1.2.3", "accept"=>"*/*", "accept-encoding"=>"gzip, deflate", "content-type"=>"application/json; charset=utf-8", "content-length"=>"45"}}]
                    response = HTTPX.post(url, :json => {:name => "testuser", :salary => "123", :age => "23"})
                    @output = response.status
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
                    args = [{:Method=>"PUT", :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/update/2", :path=>"/api/v1/update/2", :query=>nil, :Body=>"{\"name\":\"testuser\",\"salary\":\"123\",\"age\":\"23\"}", :Headers=>{"user-agent"=>"httpx.rb/1.2.3", "accept"=>"*/*", "accept-encoding"=>"gzip, deflate", "content-type"=>"application/json; charset=utf-8", "content-length"=>"45"}}]
                    response = HTTPX.put(url, :json => {:name => "testuser", :salary => "123",:age => "23"})
                    @output = response.status
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
                    args = [{:Method=>"DELETE", :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/delete/1", :path=>"/api/v1/delete/1", :query=>nil, :Body=>"", :Headers=>{"user-agent"=>"httpx.rb/1.2.3", "accept"=>"*/*", "accept-encoding"=>"gzip, deflate"}}]
                    response = HTTPX.delete(url)
                    @output = response.status
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
  