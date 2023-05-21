require 'net/ldap'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/net_ldap/instrumentation'
require 'newrelic_security/instrumentation-security/io/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNetLDAP < Minitest::Test

                def test_search 
                    $event_list.clear()
                    ldap = Net::LDAP.new(
                        host: 'ldap.forumsys.com',
                        port: 389,
                        auth: {
                          method: :simple,
                          username: 'cn=read-only-admin,dc=example,dc=com',
                          password: 'password'
                        }
                    )
                    if ldap.bind
                        NewRelic::Security::Agent.logger.debug "LDAP Authenticated : #{ldap.bind.inspect}"
                    else
                        NewRelic::Security::Agent.logger.debug "LDAP Authentication FAILED."
                    end
                    base = 'dc=example,dc=com'
                    filter = '(uid=gauss)'
                    attributes = ['cn', 'mail']
                    search_params = {
                        base: base,
                        filter: filter,
                        attributes: attributes
                      }
                    # Perform the search operation
                    output = ""
                    ldap.search(search_params) do |entry|
                        output=entry.dn
                    end
                    assert_equal "uid=gauss,dc=example,dc=com", output
                    # event verify
                    case_type = "LDAP"
                    args = [{:name=> base, :filter=> filter}]
                    event_category = nil
                    expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
                    assert_equal 5, $event_list.length
                    assert_equal expected_event.caseType, $event_list[2].caseType
                    assert_equal expected_event.parameters, $event_list[2].parameters
                    assert_nil expected_event.eventCategory, $event_list[2].eventCategory
                end
                
            end
        end
    end
end
  