require 'pg'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/pg/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestPG < Minitest::Test
                @@case_type = "SQL_DB_COMMAND"
                @@event_category = "POSTGRES"
                
                def test_exec
                    $event_list.clear()
                    client = PG::Connection.open(:dbname => 'postgres', :user => 'postgres', :host => 'localhost', :port => 5433)
                    client.exec("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()

                    # CREATE event test 
                    client.exec("create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))")
                    args = [{:sql=>"create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # INSERT event test 
                    client.exec("INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com')")
                    args = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com')", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test 
                    client.exec("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    args = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # SELECT event test 
                    # data verification 
                    results = client.exec("SELECT * FROM fake_users WHERE name= 'john'")
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {"name"=>"john", "email"=>"me@john.com", "grade"=>"A", "blog"=>"http://blog.abc.com"}
                    assert_equal expected_result, @output
                    # event verification
                    args = [{:sql=>"SELECT * FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test 
                    client.exec("DELETE FROM fake_users WHERE name= 'john'") 
                    args = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # delete operation verify
                    @output = []
                    results = client.exec("SELECT * FROM fake_users")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 

                    # DROP event test 
                    client.exec("DROP TABLE fake_users") 
                    args = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                end

                def test_exec_prepared
                    $event_list.clear()
                    client = PG::Connection.new(:dbname => 'postgres', :user => 'postgres', :host => 'localhost', :port => 5433)
                    client.exec("DROP TABLE IF EXISTS fake_users")
                    client.exec("create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))")
                    $event_list.clear()
                    
                    # INSERT event test
                    client.prepare('insert_statement', 'INSERT INTO fake_users (name, email, grade, blog) VALUES ($1, $2, $3, $4)')
                    results = client.exec_prepared('insert_statement', ['abc', 'me@abc.com', 'A', 'http://blog.abc.com'])
                    results.each do |row|
                        @output = row
                    end
                    #puts @output, results.inspect
                    assert_equal 1, results.cmd_tuples
                    # event verify
                    args = [{:parameters=>["abc", "me@abc.com", "A", "http://blog.abc.com"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test
                    client.prepare('update_statement', 'UPDATE fake_users SET name = $1, email= $2 WHERE name = $3')
                    results = client.exec_prepared('update_statement', ['john', 'me@john.com', 'abc'])
                    results.each do |row|
                        @output = row
                    end
                    #puts @output, results.inspect
                    assert_equal 1, results.cmd_tuples
                    # event verify
                    args = [{:parameters=>["john", "me@john.com", "abc"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                     # SELECT event test 
                    # data verification 
                    client.prepare('select_statement', 'SELECT * FROM fake_users WHERE name = $1')
                    results = client.exec_prepared('select_statement', ['john'])
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {"name"=>"john", "email"=>"me@john.com", "grade"=>"A", "blog"=>"http://blog.abc.com"}
                    assert_equal expected_result, @output
                    # event verification
                    args = [{:parameters=>["john"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test 
                    client.prepare('delete_statement', 'DELETE FROM fake_users WHERE name= $1')
                    results = client.exec_prepared('delete_statement', ['john'])
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {"name"=>"john", "email"=>"me@john.com", "grade"=>"A", "blog"=>"http://blog.abc.com"}
                    assert_equal expected_result, @output
                    args = [{:parameters=>["john"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory                
                    # delete operation verify
                    @output = []
                    results = client.exec("SELECT * FROM fake_users")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 
                    
                    # DROP event test 
                    client.exec("DROP TABLE fake_users") 
                    args = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                end

            end
        end
    end
end
  