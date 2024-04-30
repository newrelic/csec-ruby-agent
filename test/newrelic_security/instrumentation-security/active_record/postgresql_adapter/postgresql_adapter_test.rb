require 'rails'
require 'pg'
require 'docker'
require 'active_record'
require "active_record/connection_adapters/postgresql_adapter"
require_relative '../../../../test_helper'
require 'newrelic_security/instrumentation-security/active_record/postgresql_adapter/instrumentation'

class NewUser < ActiveRecord::Base
end

module NewRelic::Security
    module Test
        module Instrumentation
            class TestPostgresqlAdapter < Minitest::Test
                @@before_all_flag = false
    
                def setup
                    unless @@before_all_flag
                        before_all
                        @@before_all_flag = true
                    end
                end

                def before_all
                    # server setup
                    pg_config = {
                        'Image' => 'postgres:latest',
                        'name' => 'pg_test',
                        'Env' => ['POSTGRES_HOST_AUTH_METHOD=trust'],
                        'HostConfig' => {
                            'PortBindings' => {
                            '5432/tcp' => [{ 'HostPort' => '5433' }]
                            }
                        }
                    }
                    image = Docker::Image.create('fromImage' => 'postgres:latest')
                    image.refresh!
                    begin
                        Docker::Container.get('pg_test').remove(force: true)
                    rescue
                    end
                    container = Docker::Container.create(pg_config)
                    container.start
                    sleep 5
                    $event_list.clear()
                end

                def test_exec_query_exec_update_exec_delete
                    ActiveRecord::Base.establish_connection adapter: 'postgresql', database: 'postgres', :port => 5433, :host => 'localhost', :user => 'postgres'
                    load  __dir__ + '/db/schema.rb'
                    NewUser.delete_all
                    $event_list.clear()

                    # INSERT test
                    if RUBY_VERSION < '2.5.0'
                        NewUser.create(id: 1, email: 'me@john.com', name: 'John', ssn: '11')
                        # event verify 
                        args1 = [{:sql=>"INSERT INTO \"new_users\" (\"id\", \"name\", \"email\", \"ssn\") VALUES ($1, $2, $3, $4) RETURNING \"id\"", :parameters=>["1", "John", "me@john.com", "11"]}]
                        expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                        assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                        # insert event
                        assert_equal expected_event1.caseType, $event_list[0].caseType
                        assert_equal expected_event1.parameters, $event_list[0].parameters
                        assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    else
                        NewUser.insert(
                        { id: 1,
                        email: 'me@john.com',
                        name: 'John',
                        ssn: '11' }
                    )
                        # insert event 
                        args1 = [{:sql=>"INSERT INTO \"new_users\" (\"id\",\"email\",\"name\",\"ssn\") VALUES (1, 'me@john.com', 'John', '11') ON CONFLICT  DO NOTHING RETURNING \"id\"", :parameters=>[]}]
                        expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                        assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                        assert_equal expected_event1.caseType, $event_list[0].caseType
                        assert_equal expected_event1.parameters, $event_list[0].parameters
                        assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    end
                    $event_list.clear()
                    
                    # SELECT test         
                    output = NewUser.find(1)
                    # data verify 
                    assert_equal 1, output.id
                    assert_equal "John", output.name
                    assert_equal "me@john.com", output.email
                    assert_equal "11", output.ssn
                    # exec_query event verify 
                    args1 = [{:sql=>"SELECT \"new_users\".* FROM \"new_users\" WHERE \"new_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"select statement from pg_prepared_statements where name = 'a2'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, POSTGRES)
                    expected_sql_list = args1[0][:sql].split(" ")
                    puts "$event_list : #{$event_list.inspect}"
                    assert_equal 2, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    sql_fetch_list1 = $event_list[0].parameters[0][:sql].split(" ")
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_sql_list, sql_fetch_list1
                    assert_equal expected_event1.parameters[0][:parameters], $event_list[0].parameters[0][:parameters]
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  

                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory  

                    sql_fetch_list2 = $event_list[2].parameters[0][:sql].split(" ")
                    assert_equal expected_event1.caseType, $event_list[2].caseType
                    assert_equal expected_sql_list, sql_fetch_list2
                    assert_equal expected_event1.parameters[0][:parameters], $event_list[2].parameters[0][:parameters]
                    assert_equal expected_event1.eventCategory, $event_list[2].eventCategory  
                    $event_list.clear()

                    # UPDATE test           
                    output = NewUser.update(1, name: "Jack")
                    # data verify 
                    assert_equal 1, output.id
                    assert_equal "Jack", output.name
                    assert_equal "me@john.com", output.email
                    assert_equal "11", output.ssn
                    # exec_update event verify
                    args1 = [{:sql=>"SELECT \"new_users\".* FROM \"new_users\" WHERE \"new_users\".\"id\" = $1 LIMIT $2", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"select statement from pg_prepared_statements where name = 'a2'", :parameters=>[]}]
                    args3 = [{:sql=>"UPDATE \"new_users\" SET \"name\" = $1 WHERE \"new_users\".\"id\" = $2", :parameters=>["Jack", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, POSTGRES)
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args3, POSTGRES)
                    expected_sql_list = args1[0][:sql].split(" ")

                    assert_equal 4, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    # select event
                    sql_fetch_list1 = $event_list[0].parameters[0][:sql].split(" ")
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_sql_list, sql_fetch_list1
                    assert_equal expected_event1.parameters[0][:parameters], $event_list[0].parameters[0][:parameters]
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory 
                    
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory 
                    assert_equal expected_event2.parameters, $event_list[1].parameters

                    sql_fetch_list2 = $event_list[2].parameters[0][:sql].split(" ")
                    assert_equal expected_event1.caseType, $event_list[2].caseType
                    assert_equal expected_event1.eventCategory, $event_list[2].eventCategory
                    assert_equal expected_sql_list, sql_fetch_list2
                    assert_equal expected_event1.parameters[0][:parameters], $event_list[2].parameters[0][:parameters]
                    
                    # update event 
                    assert_equal expected_event3.caseType, $event_list[3].caseType
                    assert_equal expected_event3.eventCategory, $event_list[3].eventCategory 
                    assert_equal expected_event3.parameters, $event_list[3].parameters
                    $event_list.clear()

                    # DELETE test           
                    output = NewUser.delete(1)
                    # data verify 
                    assert_equal 1, output
                    # event verify
                    args1 = [{:sql=>"DELETE FROM \"new_users\" WHERE \"new_users\".\"id\" = $1", :parameters=>["1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()
                end

                def test_execute
                    ActiveRecord::Base.establish_connection adapter: 'postgresql', database: 'postgres', :port => 5433, :host => 'localhost', :user => 'postgres'
                    load  __dir__ + '/db/schema.rb'
                    NewUser.delete_all

                    # INSERT test
                    $event_list.clear()
                    ActiveRecord::Base.connection.execute("INSERT INTO new_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')")
                    # execute event verify 
                    args1 = [{:sql=>"INSERT INTO new_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # UPDATE test
                    ActiveRecord::Base.connection.execute("UPDATE new_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    # execute event verify 
                    args1 = [{:sql=>"UPDATE new_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    $event_list.clear()

                    # SELECT event test 
                    # data verification 
                    results = ActiveRecord::Base.connection.execute("SELECT * FROM new_users")
                    output = []
                    results.each do |row|
                        output = row
                    end
                    expected_result = {"id"=>1, "name"=>"John", "email"=>"me@abc.com", "ssn"=>"11"}
                    assert_equal expected_result, output
                    # event verification
                    args = [{:sql=>"SELECT * FROM new_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args, POSTGRES)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE test
                    ActiveRecord::Base.connection.execute("DELETE FROM new_users WHERE name= 'john'")
                    # execute event verify 
                    args1 = [{:sql=>"DELETE FROM new_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, POSTGRES)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory  
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()
                end

                Minitest.after_run do
                    # remove server
                    begin
                       Docker::Container.get('pg_test').remove(force: true)
                    rescue
                    end
                end
                
            end
        end
    end
end
