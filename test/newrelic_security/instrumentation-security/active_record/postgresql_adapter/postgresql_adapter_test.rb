require 'rails'
require 'pg'
require 'active_record'
require_relative '../../../../test_helper'
     
class FakeUser < ActiveRecord::Base
end

# test setup
test_file_path = __dir__ 
ActiveRecord::Base.establish_connection adapter: 'postgresql', database: 'postgres', :port => 5433, :host => 'localhost', :user => 'postgres'
load  test_file_path +'/db/schema.rb'

require 'newrelic_security/instrumentation-security//active_record/postgresql_adapter/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestPostgresqlAdapter < Minitest::Test
                @@case_type = "SQL_DB_COMMAND"
                @@event_category = "POSTGRES"

                def test_exec_query_exec_update_exec_delete
                    FakeUser.delete_all
                    $event_list.clear()

                    # INSERT test
                    result = FakeUser.insert(
                        { id: 1,
                        email: 'me@john.com',
                        name: 'John',
                        ssn: '11' }
                    )
                    # puts "result : #{result.inspect}"
                    # exec_query event verify 
                    args1 = [{:sql=>"INSERT INTO \"fake_users\" (\"id\",\"email\",\"name\",\"ssn\") VALUES (1, 'me@john.com', 'John', '11') ON CONFLICT  DO NOTHING RETURNING \"id\"", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()
                    
                    # SELECT test           
                    @output = FakeUser.find(1)
                    # puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output.id
                    assert_equal "John", @output.name
                    assert_equal "me@john.com", @output.email
                    assert_equal "11", @output.ssn
                    # exec_query event verify 
                    args1 = [{:sql=>"SELECT \"fake_users\".* FROM \"fake_users\" WHERE \"fake_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    #puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # UPDATE test           
                    @output = FakeUser.update(1, name: "Jack")
                    # puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output.id
                    assert_equal "Jack", @output.name
                    assert_equal "me@john.com", @output.email
                    assert_equal "11", @output.ssn
                    # exec_update event verify
                    args1 = [{:sql=>"SELECT \"fake_users\".* FROM \"fake_users\" WHERE \"fake_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"UPDATE \"fake_users\" SET \"name\" = $1 WHERE \"fake_users\".\"id\" = $2", :parameters=>["Jack", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    # puts $event_list.length
                    assert_equal 2, $event_list.length
                    # select event
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory 
                    # update event 
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory 
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    $event_list.clear()

                    # DELETE test           
                    @output = FakeUser.delete(1)
                    # puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output
                    # event verify
                    args1 = [{:sql=>"DELETE FROM \"fake_users\" WHERE \"fake_users\".\"id\" = $1", :parameters=>["1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()
                end

                def test_execute
                    FakeUser.delete_all

                    # INSERT test
                    $event_list.clear()
                    ActiveRecord::Base.connection.execute("INSERT INTO fake_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')")
                    # puts "result : #{result.inspect}"
                    # execute event verify 
                    args1 = [{:sql=>"INSERT INTO fake_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # UPDATE test
                    ActiveRecord::Base.connection.execute("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    # puts "result : #{result.inspect}"
                    # execute event verify 
                    args1 = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # SELECT event test 
                    # data verification 
                    results = ActiveRecord::Base.connection.execute("SELECT * FROM fake_users")
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {"id"=>1, "name"=>"John", "email"=>"me@abc.com", "ssn"=>"11"}
                    assert_equal expected_result, @output
                    # event verification
                    args = [{:sql=>"SELECT * FROM fake_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE test
                    ActiveRecord::Base.connection.execute("DELETE FROM fake_users WHERE name= 'john'")
                    # puts "result : #{result.inspect}"
                    # execute event verify 
                    args1 = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()
                end
            end
        end
    end
end
