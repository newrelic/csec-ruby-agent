require 'rails'
require 'pg'
require 'docker'
require 'active_record'
require_relative '../../../../test_helper'
require 'newrelic_security/instrumentation-security/pg/instrumentation'

class NewUser < ActiveRecord::Base
end

$pg_config = {
  'Image' => 'postgres:latest',
  'name' => 'pg_test',
  'Env' => ['POSTGRES_HOST_AUTH_METHOD=trust'],
  'HostConfig' => {
    'PortBindings' => {
      '5432/tcp' => [{ 'HostPort' => '5433' }]
    }
  }
}

# test setup
$test_file_path = __dir__ 
ActiveRecord::Base.establish_connection adapter: 'postgresql', database: 'postgres', :port => 5433, :host => 'localhost', :user => 'postgres'
require 'newrelic_security/instrumentation-security//active_record/postgresql_adapter/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestPostgresqlAdapter < Minitest::Test
                @@case_type = "SQL_DB_COMMAND"
                @@event_category = "POSTGRES"

                def test_exec_query_exec_update_exec_delete
                    # server setup
                    begin
                        Docker::Container.get('pg_test').remove(force: true)
                    rescue
                    end
                    container = Docker::Container.create($pg_config)
                    container.start
                    sleep 5

                    ActiveRecord::Base.establish_connection adapter: 'postgresql', database: 'postgres', :port => 5433, :host => 'localhost', :user => 'postgres'
                    load  $test_file_path +'/db/schema.rb'
                    NewUser.delete_all
                    $event_list.clear()

                    # INSERT test
                    result = NewUser.insert(
                        { id: 1,
                        email: 'me@john.com',
                        name: 'John',
                        ssn: '11' }
                    )
                    # puts "result : #{result.inspect}"
                    # exec_query event verify 
                    args1 = [{:sql=>"INSERT INTO \"new_users\" (\"id\",\"email\",\"name\",\"ssn\") VALUES (1, 'me@john.com', 'John', '11') ON CONFLICT  DO NOTHING RETURNING \"id\"", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()
                    
                    # SELECT test         
                    @output = NewUser.find(1)
                    # puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output.id
                    assert_equal "John", @output.name
                    assert_equal "me@john.com", @output.email
                    assert_equal "11", @output.ssn
                    # exec_query event verify 
                    args1 = [{:sql=>"SELECT \"new_users\".* FROM \"new_users\" WHERE \"new_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"select statement from pg_prepared_statements where name = 'a2'", :parameters=>[]}]
                    args3 = [{:sql=>"SELECT \"new_users\".* FROM \"new_users\" WHERE \"new_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    #puts $event_list.length
                    assert_equal 3, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory  
                    assert_equal expected_event3.caseType, $event_list[2].caseType
                    assert_equal expected_event3.parameters, $event_list[2].parameters
                    assert_equal expected_event3.eventCategory, $event_list[2].eventCategory  
                    $event_list.clear()

                    # UPDATE test           
                    @output = NewUser.update(1, name: "Jack")
                    # puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output.id
                    assert_equal "Jack", @output.name
                    assert_equal "me@john.com", @output.email
                    assert_equal "11", @output.ssn
                    # exec_update event verify
                    args1 = [{:sql=>"SELECT \"new_users\".* FROM \"new_users\" WHERE \"new_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"select statement from pg_prepared_statements where name = 'a2'", :parameters=>[]}]
                    args3 = [{:sql=>"SELECT \"new_users\".* FROM \"new_users\" WHERE \"new_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    args4 = [{:sql=>"UPDATE \"new_users\" SET \"name\" = $1 WHERE \"new_users\".\"id\" = $2", :parameters=>["Jack", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    expected_event4 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args4, @@event_category)
                    # puts $event_list.length
                    assert_equal 4, $event_list.length
                    # select event
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory 
                    
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory 
                    assert_equal expected_event2.parameters, $event_list[1].parameters

                    assert_equal expected_event3.caseType, $event_list[2].caseType
                    assert_equal expected_event3.eventCategory, $event_list[2].eventCategory 
                    assert_equal expected_event3.parameters, $event_list[2].parameters
                    # update event 
                    assert_equal expected_event4.caseType, $event_list[3].caseType
                    assert_equal expected_event4.eventCategory, $event_list[3].eventCategory 
                    assert_equal expected_event4.parameters, $event_list[3].parameters
                    $event_list.clear()

                    # DELETE test           
                    @output = NewUser.delete(1)
                    # puts "output::", @output.inspect,"\n\n\n"
                    # data verify 
                    assert_equal 1, @output
                    # event verify
                    args1 = [{:sql=>"DELETE FROM \"new_users\" WHERE \"new_users\".\"id\" = $1", :parameters=>["1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()

                    # remove server
                    container.stop
                    container.delete
                end

                def test_execute
                    # server setup
                    begin
                        Docker::Container.get('pg_test').remove(force: true)
                    rescue
                    end
                    container = Docker::Container.create($pg_config)
                    container.start
                    sleep 5
                    
                    ActiveRecord::Base.establish_connection adapter: 'postgresql', database: 'postgres', :port => 5433, :host => 'localhost', :user => 'postgres'
                    load  $test_file_path +'/db/schema.rb'
                    NewUser.delete_all

                    # INSERT test
                    $event_list.clear()
                    ActiveRecord::Base.connection.execute("INSERT INTO new_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')")
                    # puts "result : #{result.inspect}"
                    # execute event verify 
                    args1 = [{:sql=>"INSERT INTO new_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # UPDATE test
                    ActiveRecord::Base.connection.execute("UPDATE new_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    # puts "result : #{result.inspect}"
                    # execute event verify 
                    args1 = [{:sql=>"UPDATE new_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # SELECT event test 
                    # data verification 
                    results = ActiveRecord::Base.connection.execute("SELECT * FROM new_users")
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {"id"=>1, "name"=>"John", "email"=>"me@abc.com", "ssn"=>"11"}
                    assert_equal expected_result, @output
                    # event verification
                    args = [{:sql=>"SELECT * FROM new_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE test
                    ActiveRecord::Base.connection.execute("DELETE FROM new_users WHERE name= 'john'")
                    # puts "result : #{result.inspect}"
                    # execute event verify 
                    args1 = [{:sql=>"DELETE FROM new_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    # puts $event_list.length
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()

                    # remove server
                    container.stop
                    container.delete
                end
            end
        end
    end
end
