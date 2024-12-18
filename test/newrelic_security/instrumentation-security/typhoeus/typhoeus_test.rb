require 'typhoeus'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/ethon/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestTyphoeus < Minitest::Test

                def setup
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                end

                def test_get
                    url = "http://www.google.com?q=test"
                    args = ["http://www.google.com?q=test"]
                    response = Typhoeus.get(url) # input=https://www.google.com
                    assert_equal 200, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_ssl
                    url = "https://www.google.com?q=test"
                    args = ["https://www.google.com?q=test"]
                    response = Typhoeus.get(url) # input=https://www.google.com
                    assert_equal 200, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_post_json
                    url = "http://localhost:9291/books"
                    args = ["http://localhost:9291/books?field1=a%20field"]
                    data = {"title"=>"New", "author"=>"New Author"}
                    request = Typhoeus::Request.new(
                      url,
                      method: :post,
                      body: data.to_json,
                      params: { field1: "a field" },
                      headers: { 'Content-Type': "application/json" }
                    )
                    response = request.run
                    assert_equal 201, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_put_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1?field1=a%20field"]
                    data = {"title"=>"Update Book", "author"=>"Update Author"}
                    request = Typhoeus::Request.new(
                      url,
                      method: :put,
                      body: data.to_json,
                      params: { field1: "a field" },
                      headers: { 'Content-Type': "application/json" }
                    )
                    response = request.run
                    assert_equal 200, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_delete_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    request = Typhoeus::Request.new(
                      url,
                      method: :delete
                    )
                    response = request.run
                    assert_equal 204, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_typhoeus_hydra
                    url = "https://www.google.com?q=test"
                    args = ["https://www.google.com?q=test"]
                    hydra = Typhoeus::Hydra.hydra
                    request = Typhoeus::Request.new(url)
                    hydra.queue(request)    
                    hydra.run
                    assert_equal 200, request.response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def teardown
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end

            end
        end
    end
end
  