require 'excon'
require 'faraday'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/excon/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestExcon < Minitest::Test
                def test_excon
                    $event_list.clear()
                    url = "https://www.google.com"
                    @output = Excon.get(url).body
                    case_type = "HTTP_REQUEST"
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"www.google.com", :path=>"", :query=>nil, :Body=>nil}]
                    event_category = nil
                    expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:host], $event_list[0].parameters[0][:host]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:path], $event_list[0].parameters[0][:path]
                    assert_nil expected_event.parameters[0][:query], $event_list[0].parameters[0][:query]
                    assert_nil expected_event.parameters[0][:Body], $event_list[0].parameters[0][:Body]
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end
                
                # def test_faraday_excon
                #     url = "https://www.google.com"
                #     conn = Faraday.new(:url => url) do |faraday|
                #         faraday.request  :url_encoded             # form-encode POST params
                #         faraday.response :logger                  # log requests to $stdout
                #         faraday.adapter  Faraday::Adapter::Excon # make requests with Net::HTTP
                #     end
                # end
            end
        end
    end
end
  