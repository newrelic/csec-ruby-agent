return if RUBY_ENGINE == 'jruby'
require 'patron'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/patron/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestPatron < Minitest::Test

                def setup
                    $event_list.clear()
                end

                def test_patron_session_get
                    url = "https://www.google.com"
                    sess = Patron::Session.new({ :timeout => 10,
                                            :base_url => url,
                                            :headers => {'User-Agent' => 'myapp/1.0'} } )
                    @output = sess.get("/").body
                    #puts @output
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com/", :path=>"/", :query=>nil, :Body=>nil, :Headers=>{"Expect"=>""}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(HTTP_REQUEST, args, nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(HTTP_REQUEST)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
            end
        end
    end
end
