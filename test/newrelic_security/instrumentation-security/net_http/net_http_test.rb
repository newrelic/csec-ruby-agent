require 'net/http/persistent'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/net_http/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNetHTTP < Minitest::Test

                # def test_get
                #     url = "http://www.google.com"
                #     @output = Net::HTTP.get(url,'/index.html')
                #     puts @output
                # end

                def setup
                    $event_list.clear()
                end

                def test_get_request
                    url = "http://www.google.com"
                    uri = URI.parse("#{url}")
                    http = Net::HTTP.new(uri.host, uri.port)
                    request = Net::HTTP::Get.new(uri.request_uri)
                    response = http.request(request)
                    assert_equal "200", response.code
                    args = ["http://www.google.com:80/"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_uri
                    url = "http://www.google.com"
                    uri = URI(url)
                    @output = Net::HTTP.get(uri)
                    #puts @output
                    args = ["http://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_response_dynamic
                    url = "http://www.google.com"
                    uri = URI(url)
                    uri_params = { :limit => 10, :page => 3 }
	                uri.query = URI.encode_www_form(uri_params)
                    @output = Net::HTTP.get_response(uri)
                    assert_equal "200", @output.code
                    args = ["http://www.google.com?limit=10&page=3"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
                
                def test_get_start
                    url = "http://www.google.com"
                    uri = URI(url)
                    Net::HTTP.start(uri.host, uri.port) do |http|
                        request = Net::HTTP::Get.new uri
                        # http.use_ssl = true
                        @output = http.request(request)
                    end
                    assert_equal "200", @output.code
                    args = ["http://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_get_start_ssl
                    url = "http://www.google.com"
                    uri = URI(url)
                    Net::HTTP.start(uri.host, uri.port, :use_ssl => uri.scheme == 'https') do |http|
                        request = Net::HTTP::Get.new uri
                        @output = http.request(request)
                    end
                    assert_equal "200", @output.code
                    args = ["http://www.google.com"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                def test_persistent_request
                    url = "http://www.google.com"
                    http = Net::HTTP::Persistent.new name: 'my_app_name'
                    uri = URI(url)
                    response = http.request(uri)
                    @output = response.code
                    assert_equal "200", @output
                    args = ["http://www.google.com:80/"]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end

                # def test_open
                #     $event_list.clear()
                #     url = "https://www.google.com"
                #     @output = open(url,:proxy => nil).read
                #     puts @output
                #     #assert_equal "200", @output
                # end
            end
        end
    end
end
  