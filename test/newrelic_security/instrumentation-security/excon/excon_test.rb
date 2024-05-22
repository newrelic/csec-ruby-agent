require 'excon'
require 'faraday'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/excon/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestExcon < Minitest::Test
                def setup
                    $event_list.clear()
                end

                def test_excon
                    skip("Skipping for ruby 2.4.10 && instrumentation method chain") if RUBY_VERSION == '2.4.10' && ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == 'chain'
                    url = "http://google.com"
                    @output = Excon.get(url).body
                    args = [{:Method=>:get, :scheme=>"http", :host=>"google.com", :port=>80, :URI=>"google.com", :path=>"", :query=>nil, :Body=>nil}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters[0][:Method], $event_list[0].parameters[0][:Method]
                    assert_equal expected_event.parameters[0][:scheme], $event_list[0].parameters[0][:scheme]
                    assert_equal expected_event.parameters[0][:host], $event_list[0].parameters[0][:host]
                    assert_equal expected_event.parameters[0][:port], $event_list[0].parameters[0][:port]
                    assert_equal expected_event.parameters[0][:URI], $event_list[0].parameters[0][:URI]
                    assert_equal expected_event.parameters[0][:path], $event_list[0].parameters[0][:path]
                    assert_nil $event_list[0].parameters[0][:query]
                    assert_nil $event_list[0].parameters[0][:Body]
                    assert_nil $event_list[0].eventCategory
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
  