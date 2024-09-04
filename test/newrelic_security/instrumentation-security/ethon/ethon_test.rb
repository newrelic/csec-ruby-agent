require 'ethon'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/ethon/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestEthonEasy < Minitest::Test

                def setup
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                end

                def test_get
                    url = "http://www.google.com"
                    args = ["https://www.google.com"]
                    easy = Ethon::Easy.new(url: url)
                    response = easy.perform
                    @output = response
                    assert_equal :ok, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_ssl
                    url = "https://www.google.com"
                    args = ["https://www.google.com"]
                    easy = Ethon::Easy.new(url: url)
                    response = easy.perform
                    @output = response
                    assert_equal :ok, @output
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_post_json
                    url = "http://localhost:9291/books"
                    args = ["http://localhost:9291/books"]
                    # response = HTTPX.post(url, :json => {:name => "testuser", :salary => "123", :age => "23"})
                    easy = Ethon::Easy.new
                    easy.http_request(url, :post, body: '{"title" : "New Book", "author": "New Author"}')
                    easy.headers = {'Content-Type' => 'application/json'}
                    response = easy.perform
                    assert_equal :ok, response
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_put_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    # response = HTTPX.put(url, :json => {:name => "testuser", :salary => "123",:age => "23"})
                    easy = Ethon::Easy.new
                    easy.http_request(url, :put, { body: '{"title": "Update Book", "author": "Update Author"}'})
                    easy.headers = {'Content-Type' => 'application/json'}
                    response = easy.perform
                    assert_equal :ok, response
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_delete_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    # response = HTTPX.delete(url)
                    easy = Ethon::Easy.new
                    easy.http_request(url, :delete)
                    easy.headers = {'User-Agent' => 'ethon'}
                    response = easy.perform
                    assert_equal :ok, response
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def teardown
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end
            end

            class TestEthonMulti < Minitest::Test
                def setup
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                end

                def test_get
                    url = "http://www.google.com"
                    args = ["http://www.google.com", "https://newrelic.com"]

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
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
                
                def teardown
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end
            end

        end
    end
end
  