require 'net/http/persistent'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/net_http/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNetHTTP < Minitest::Test
                @@case_type = "HTTP_REQUEST"
                @@args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :path=>"/", :query=>nil, :URI=>"http://www.google.com:80/", :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby", "connection"=>"close"}}]
                @@event_category = nil

                # def test_get
                #     url = "http://www.google.com"
                #     @output = Net::HTTP.get(url,'/index.html')
                #     puts @output
                # end

                def test_get_request
                    $event_list.clear()
                    url = "http://www.google.com"
                    uri = URI.parse("#{url}")
                    http = Net::HTTP.new(uri.host, uri.port)
                    request = Net::HTTP::Get.new(uri.request_uri)
                    response = http.request(request)
                    @output = response.code
                    assert_equal "200", @output

                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, @@args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end

                def test_get_uri
                    $event_list.clear()
                    url = "http://www.google.com"
                    uri = URI(url)
                    @output = Net::HTTP.get(uri)
                    #puts @output
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby", "host"=>"www.google.com"}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end

                def test_get_response_dynamic
                    $event_list.clear()
                    url = "http://www.google.com"
                    uri = URI(url)
                    uri_params = { :limit => 10, :page => 3 }
	                uri.query = URI.encode_www_form(uri_params)
                    @output = Net::HTTP.get_response(uri)
                    assert_equal "200", @output.code
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com?limit=10&page=3", :path=>"", :query=>"limit=10&page=3", :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby", "host"=>"www.google.com"}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end
                
                def test_get_start
                    $event_list.clear()
                    url = "http://www.google.com"
                    uri = URI(url)
                    Net::HTTP.start(uri.host, uri.port) do |http|
                        request = Net::HTTP::Get.new uri
                        # http.use_ssl = true
                        @output = http.request(request)
                    end
                    assert_equal "200", @output.code
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby", "host"=>"www.google.com"}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end

                def test_get_start_ssl
                    $event_list.clear()
                    url = "http://www.google.com"
                    uri = URI(url)
                    Net::HTTP.start(uri.host, uri.port, :use_ssl => uri.scheme == 'https') do |http|
                        request = Net::HTTP::Get.new uri
                        @output = http.request(request)
                    end
                    assert_equal "200", @output.code
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :URI=>"http://www.google.com", :path=>"", :query=>nil, :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby", "host"=>"www.google.com"}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
                end

                def test_persistent_request
                    $event_list.clear()
                    url = "http://www.google.com"
                    http = Net::HTTP::Persistent.new name: 'my_app_name'
                    uri = URI(url)
                    response = http.request(uri)
                    @output = response.code
                    assert_equal "200", @output
                    args = [{:Method=>"GET", :scheme=>"http", :host=>"www.google.com", :port=>80, :path=>"/", :query=>nil, :URI=>"http://www.google.com:80/", :Body=>nil, :Headers=>{"accept-encoding"=>"gzip;q=1.0,deflate;q=0.6,identity;q=0.3", "accept"=>"*/*", "user-agent"=>"Ruby", "connection"=>"keep-alive", "keep-alive"=>"30"}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 2, $event_list.length
                    assert_equal expected_event.caseType, $event_list[1].caseType
                    assert_equal expected_event.parameters, $event_list[1].parameters
                    assert_nil expected_event.eventCategory, $event_list[1].eventCategory
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
  