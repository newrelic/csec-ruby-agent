require 'rails'
require 'sqlite3'
require 'active_record'
require_relative '../../../../test_helper'
     
class FakeUser < ActiveRecord::Base
end

# test setup
test_file_path = __dir__ 
database_name = test_file_path + "/db/test.db"
#test_db = SQLite3::Database.new(database_name)
ActiveRecord::Base.establish_connection adapter: 'sqlite3', database: database_name
load  test_file_path +'/db/schema.rb'

require 'newrelic_security/instrumentation-security//active_record/sqlite3_adapter/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestSQLite3Adapter < Minitest::Test
                @@case_type = "SQL_DB_COMMAND"
                @@event_category = "SQLITE"

                def test_exec_query 
                    FakeUser.delete_all
                    $event_list.clear()

                    # INSERT test
                    FakeUser.insert(
                        { id: 1,
                        email: 'me@john.com',
                        name: 'John',
                        ssn: '11' }
                    )
                    #puts "result : #{result.inspect}"
                    # 3 event verify 
                    args1 = [{:sql=>"SELECT sqlite_version(*)", :parameters=>[]}]
                    args2 = [{:sql=>"SELECT sql FROM\n  (SELECT * FROM sqlite_master UNION ALL\n   SELECT * FROM sqlite_temp_master)\nWHERE type = 'table' AND name = 'fake_users'\n", :parameters=>[]}]
                    args3 = [{:sql=>"INSERT INTO \"fake_users\" (\"id\",\"email\",\"name\",\"ssn\") VALUES (1, 'me@john.com', 'John', '11') ON CONFLICT  DO NOTHING", :parameters=>[]}]         
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    #puts $event_list.length
                    assert_equal 3, $event_list.length
                    # sqlite_version
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    # sqlite_master
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory 
                    # query
                    assert_equal expected_event3.caseType, $event_list[2].caseType
                    assert_equal expected_event3.parameters, $event_list[2].parameters
                    assert_equal expected_event3.eventCategory, $event_list[2].eventCategory 
                    $event_list.clear()
                    
                    # SELECT test           
                    @output = FakeUser.find(1)
                    #puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output.id
                    assert_equal "John", @output.name
                    assert_equal "me@john.com", @output.email
                    assert_equal "11", @output.ssn
                    # event verify
                    args1 = [{:sql=>"SELECT \"fake_users\".* FROM \"fake_users\" WHERE \"fake_users\".\"id\" = ? LIMIT ?", :parameters=>["1", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    #puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # UPDATE test           
                    @output = FakeUser.update(1, name: "Jack")
                    #puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output.id
                    assert_equal "Jack", @output.name
                    assert_equal "me@john.com", @output.email
                    assert_equal "11", @output.ssn
                    # event verify
                    args1 = [{:sql=>"SELECT \"fake_users\".* FROM \"fake_users\" WHERE \"fake_users\".\"id\" = ? LIMIT ?", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"UPDATE \"fake_users\" SET \"name\" = ? WHERE \"fake_users\".\"id\" = ?", :parameters=>["Jack", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    #puts $event_list.length
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
                    args1 = [{:sql=>"DELETE FROM \"fake_users\" WHERE \"fake_users\".\"id\" = ?", :parameters=>["1"]}]
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
  
