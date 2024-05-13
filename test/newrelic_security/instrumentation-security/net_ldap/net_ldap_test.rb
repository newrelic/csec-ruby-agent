require 'net/ldap'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/net_ldap/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestNetLDAP < Minitest::Test
                
                def setup
                    $event_list.clear()
                end

                def test_search 
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
                    expected_event = NewRelic::Security::Agent::Control::Event.new(LDAP, [{:name=> base, :filter=> filter}], nil)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(LDAP)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_nil $event_list[0].eventCategory
                end
                
            end
        end
    end
end
  