require 'async'
require 'async/http/internet'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/async-http/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestAsyncHTTP < Minitest::Test

                def setup
                    $event_list.clear()
                end

                def test_get
                    args = ["http://www.google.com/search?q=test"]
                    response = nil
                    Async do
                        begin
                            internet = Async::HTTP::Internet.new
                            headers = [['accept', 'application/json']]
                            response = internet.get "http://www.google.com/search?q=test", headers
                            response.read
                        rescue Exception => e
                            NewRelic::Security::Agent.logger.debug "Exception in TestAsyncHTTP.test_get : #{e} #{e.backtrace}"
                        ensure
                            internet.close
                        end
                      # TODO: Ensure without begin/end supported after RUBY_VERSION >= 2.5, remove rescue to optimize.
                    end
                    assert_equal 200, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                if RUBY_VERSION >= '2.5.0'
                    def test_get_ssl
                        args = ["https://www.google.com/search?q=test"]
                        response = nil
                        Async do
                            begin
                                internet = Async::HTTP::Internet.new
                                response = internet.get "https://www.google.com/search?q=test"
                                response.read
                            rescue Exception => e
                                NewRelic::Security::Agent.logger.debug "Exception in TestAsyncHTTP.test_get_ssl : #{e} #{e.backtrace}"
                            ensure
                                internet.close
                            end
                        end
                        assert_equal 200, response.status
                        expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                        assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                        assert_equal expected_event.caseType, $event_list[0].caseType
                        assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                        assert_nil $event_list[0].eventCategory
                    end
                end

                def test_post_json
                    url = "http://localhost:9291/books"
                    args = ["http://localhost:9291/books"]
                    data = {"title"=>"New", "author"=>"New Author"}
                    response = nil
                    Async do
                        begin
                            internet = Async::HTTP::Internet.new
                            headers = [['Content-Type', 'application/json']]
                            body = [JSON.dump(data)]
                            response = internet.post url, headers, body
                            response.read
                        rescue Exception => e
                            NewRelic::Security::Agent.logger.debug "Exception in TestAsyncHTTP.test_post_json : #{e} #{e.backtrace}"
                        ensure
                            internet.close
                        end
                    end
                    assert_equal 201, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_put_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    data = {"title"=>"Update Book", "author"=>"Update Author"}
                    response = nil
                    Async do
                        begin
                            internet = Async::HTTP::Internet.new
                            headers = [['Content-Type', 'application/json']]
                            body = [JSON.dump(data)]
                            response = internet.put url, headers, body
                            response.read
                        rescue Exception => e
                            NewRelic::Security::Agent.logger.debug "Exception in TestAsyncHTTP.test_put_json : #{e} #{e.backtrace}"
                        ensure
                            internet.close
                        end
                    end
                    assert_equal 200, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

                def test_delete_json
                    url = "http://localhost:9291/books/1"
                    args = ["http://localhost:9291/books/1"]
                    response = nil
                    Async do
                        begin
                            internet = Async::HTTP::Internet.new
                            response = internet.delete url
                            response.read
                        rescue Exception => e
                            NewRelic::Security::Agent.logger.debug "Exception in TestAsyncHTTP.test_delete_json : #{e} #{e.backtrace}"
                        ensure
                            internet.close
                        end
                    end
                    assert_equal 204, response.status
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0], $event_list[0].parameters[0]
                    assert_nil $event_list[0].eventCategory
                end

            end

        end
    end
end
  