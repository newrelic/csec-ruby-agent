require 'typhoeus'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/typhoeus/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestTyphoeus < Minitest::Test

                def test_get
                    $event_list.clear()
                    url = "http://www.google.com?q=test"
                    args = [{:Method=>:get, :URI=>"http://www.google.com?q=test", :Body=>nil, :Headers=>{"User-Agent"=>"Typhoeus - https://github.com/typhoeus/typhoeus", "Expect"=>""}, :scheme=>"http", :host=>"www.google.com", :port=>80, :path=>"", :query=>"q=test"}]
                    response = Typhoeus.get(url) # input=https://www.google.com
                    assert_equal 200, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_nil $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_get_ssl
                    $event_list.clear()
                    url = "https://www.google.com?q=test"
                    args = [{:Method=>:get, :URI=>"https://www.google.com?q=test", :Body=>nil, :Headers=>{"User-Agent"=>"Typhoeus - https://github.com/typhoeus/typhoeus", "Expect"=>""}, :scheme=>"https", :host=>"www.google.com", :port=>443, :path=>"", :query=>"q=test"}]
                    response = Typhoeus.get(url) # input=https://www.google.com
                    assert_equal 200, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_nil $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_post_json
                    $event_list.clear()
                    url = "http://localhost:9291/books"
                    args = [{:Method=>:post, :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books", :path=>"/books", :query=>nil, :Body=>"{\"title\":\"New\",\"author\":\"New Author\"}", :Headers=>{:"Content-Type"=>"application/json"}}]
                    data = {"title"=>"New","author"=>"New Author"}
                    request = Typhoeus::Request.new(
                        url,
                        method: :post,
                        body: data.to_json,
                        params: { field1: "a field" },
                        headers: { "Content-Type": "application/json" }
                    )
                    response = request.run
                    assert_equal 201, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
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
                    args = [{:Method=>:put, :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/books/1", :query=>nil, :Body=>"{\"title\":\"Update Book\",\"author\":\"Update Author\"}", :Headers=>{:"Content-Type"=>"application/json"}}]
                    data = {"title"=>"Update Book","author"=>"Update Author"}
                    request = Typhoeus::Request.new(
                        url,
                        method: :put,
                        body: data.to_json,
                        params: { field1: "a field" },
                        headers: { "Content-Type": "application/json" }
                    )
                    response = request.run
                    assert_equal 200, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
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
                    args = [{:Method=>:delete, :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/api/v1/delete/1", :query=>nil, :Body=>nil, :Headers=>{}}]
                    request = Typhoeus::Request.new(
                        url,
                        method: :delete
                    )
                    response = request.run
                    assert_equal 204, response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_nil $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                def test_typhoeus_hydra
                    $event_list.clear()
                    url = "https://www.google.com?q=test"
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com?q=test", :path=>"", :query=>"q=test", :Body=>nil, :Headers=>{"User-Agent"=>"Typhoeus - https://github.com/typhoeus/typhoeus", "Expect"=>""}}]
                    hydra = Typhoeus::Hydra.hydra
                    request = Typhoeus::Request.new(url)
                    hydra.queue(request)
                    response = hydra.run
                    assert_equal 200, request.response.response_code
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_nil $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

            end
        end
    end
end
  