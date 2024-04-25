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
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end

                if RUBY_VERSION >= '2.5.0'
                    def test_get_ssl
                        $event_list.clear()
                        url = "http://www.google.com"
                        args = [{:Method=>"GET", :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com/search?q=test", :path=>"/search", :query=>"q=test", :Body=>"", :Headers=>{"accept"=>"application/json"}}]
                        response = nil
                        Async do
                            begin
                                internet = Async::HTTP::Internet.new
                                headers = [['accept', 'application/json']]
                                response = internet.get "https://www.google.com/search?q=test"#, headers
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
                        assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                        assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                        assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                        assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                        assert_equal expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                        assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                    end
                end

                def test_post_json
                    $event_list.clear()
                    url = "http://localhost:9291/books"
                    args = [{:Method=>"POST", :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books", :path=>"/books", :query=>nil, :Body=>"{\"title\":\"New\",\"author\":\"New Author\"}", :Headers=>{"Content-Type"=>"application/json"}}]
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
                    args = [{:Method=>"PUT", :scheme=>"http", :host=>"localhost", :port=>9291, :URI=>"http://localhost:9291/books/1", :path=>"/books/1", :query=>nil, :Body=>"{\"title\":\"Update Book\",\"author\":\"Update Author\"}", :Headers=>{"Content-Type"=>"application/json"}}]
                    data = {"title"=>"Update Book","author"=>"Update Author"}
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
  