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
                    #TODO ldap server  
                    input = "abc"
                    user,psw = "bob", "secret"
                    ldap = Net::LDAP.new
                    ldap.host = "localhost"
                    ldap.port = 8080
                    #ldap.auth "cn=read-only-admin,dc=example,dc=org", "password"
                    result = ldap.bind_as(
                        :base => "dc=example,dc=org",
                        :filter => "(uid=#{user})",
                        :password => psw
                    )
                    if result
                        NewRelic::Security::Agent.logger.debug "LDAP Authenticated : #{result.first.dn}"
                    else
                        NewRelic::Security::Agent.logger.debug "LDAP Authentication FAILED."
                    end
                    treebase = "dc=example,dc=org"
                    filter = "(|(uid=#{input}))"
                    attrs = ["sn", "objectclass"]
                    @output=""
                    ldap.search( :base => treebase, :filter => filter, :attributes => attrs, :return_result => false ) do |entry|
                        puts "DN: #{entry.dn}"
                        @output=@output+entry.dn+"\n"
                        entry.each do |attr, values|
                            puts ".......#{attr}:"
                            values.each do |value|
                            puts "          #{value}"
                            end
                        end
                    end
                    #@output=@output.split("\n")
                    #puts "output: #{@output}"

                    # event verify
                    case_type = "LDAP"
                    args = [{:name=>"dc=example,dc=org", :filter=>"(uid=bob)"}]
                    args2 = [{:name=>"dc=example,dc=org", :filter=>"(|(uid=abc))"}]
                    event_category = nil
                    expected_event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(case_type, args2, event_category)
                    assert_equal 6, $event_list.length
                    assert_equal expected_event.caseType, $event_list[2].caseType
                    assert_equal expected_event.parameters, $event_list[2].parameters
                    assert_nil expected_event.eventCategory, $event_list[2].eventCategory

                    assert_equal expected_event2.caseType, $event_list[3].caseType
                    assert_equal expected_event2.parameters, $event_list[3].parameters
                    assert_nil expected_event2.eventCategory, $event_list[3].eventCategory
                end
                
            end
        end
    end
end
  