require 'patron'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/patron/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestPatron < Minitest::Test
                def test_patron_session_get
                    $event_list.clear()
                    url = "https://www.google.com"
                    sess = Patron::Session.new({ :timeout => 10,
                                            :base_url => url,
                                            :headers => {'User-Agent' => 'myapp/1.0'} } )
                    @output = sess.get("/").body
                    #puts @output
                    case_type = "HTTP_REQUEST"
                    args = [{:Method=>:get, :scheme=>"https", :host=>"www.google.com", :port=>443, :URI=>"https://www.google.com/", :path=>"/", :query=>nil, :Body=>nil, :Headers=>{"Expect"=>""}}]
                    event_category = nil
                    expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil expected_event.eventCategory, $event_list[0].eventCategory
                end
            end
        end
    end
end
  