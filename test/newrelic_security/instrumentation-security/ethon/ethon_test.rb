require 'ethon'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/ethon/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestEthonEasy < Minitest::Test

                def setup
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                end

                def test_get
                    $event_list.clear()
                    url = "http://www.google.com"
                    args = [{:scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil}]
                    easy = Ethon::Easy.new(url: url)
                    response = easy.perform
                    @output = response
                    assert_equal :ok, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_get_ssl
                    $event_list.clear()
                    url = "https://www.google.com"
                    args = [{:scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com", :path=>"", :query=>nil}]
                    easy = Ethon::Easy.new(url: url)
                    response = easy.perform
                    @output = response
                    assert_equal :ok, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_post_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/create"
                    args = [{:Method=>:post, :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/create", :path=>"/api/v1/create", :query=>nil, :Body=>{:name=>"testuser", :salary=>"123", :age=>"23"}, :Headers=>{"User-Agent"=>"ethon"}}]
                    # response = HTTPX.post(url, :json => {:name => "testuser", :salary => "123", :age => "23"})
                    easy = Ethon::Easy.new
                    easy.http_request(url, :post, { body: {:name => "testuser", :salary => "123", :age => "23"}})
                    easy.headers = {'User-Agent' => 'ethon'}
                    response = easy.perform
                    assert_equal :ok, response
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_put_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/update/2"
                    args = [{:Method=>:put, :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/update/2", :path=>"/api/v1/update/2", :query=>nil, :Body=>{:name=>"testuser", :salary=>"123", :age=>"23"}, :Headers=>{"User-Agent"=>"ethon"}}]
                    # response = HTTPX.put(url, :json => {:name => "testuser", :salary => "123",:age => "23"})
                    easy = Ethon::Easy.new
                    easy.http_request(url, :put, { body: {:name => "testuser", :salary => "123", :age => "23"}})
                    easy.headers = {'User-Agent' => 'ethon'}
                    response = easy.perform
                    assert_equal :ok, response
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_delete_json
                    $event_list.clear()
                    url = "https://dummy.restapiexample.com/api/v1/delete/1"
                    args = [{:Method=>:delete, :scheme=>"https", :host=>"dummy.restapiexample.com", :port=>443, :URI=>"https://dummy.restapiexample.com/api/v1/delete/1", :path=>"/api/v1/delete/1", :query=>nil, :Body=>nil, :Headers=>{"User-Agent"=>"ethon"}}]
                    # response = HTTPX.delete(url)
                    easy = Ethon::Easy.new
                    easy.http_request(url, :delete)
                    easy.headers = {'User-Agent' => 'ethon'}
                    response = easy.perform
                    assert_equal :ok, response
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def teardown
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end
            end

            class TestEthonMulti < Minitest::Test
                def test_get
                    $event_list.clear()
                    url = "http://www.google.com"
                    args = [{:Method=>:get, :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>nil}, {:Method=>:get, :scheme=>"https", :host=>"newrelic.com", :port=>443, :URI=>"https://newrelic.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{"User-Agent"=>"ethon"}}]

                    multi = Ethon::Multi.new
                    easy = Ethon::Easy.new
                    easy.http_request(url, :get, { http_version: :httpv2_0 })
                    multi.add(easy)
  
                    # To set the server to use http2 with https and http1 with http, send the following:
                    easy = Ethon::Easy.new
                    easy.http_request("https://newrelic.com", :get, { http_version: :httpv2_tls })
                    easy.headers = {'User-Agent' => 'ethon'}
                    multi.add(easy)
            
                    response = multi.perform
                    assert_nil response
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
  