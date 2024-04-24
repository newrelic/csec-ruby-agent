require 'mysql2'
require 'docker'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/mysql2/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestMysql2 < Minitest::Test
                @@case_type = "SQL_DB_COMMAND"
                @@event_category = "MYSQL"
                @@before_all_flag = false
    
                def setup
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                    unless @@before_all_flag
                        before_all
                        @@before_all_flag = true
                    end
                end

                def before_all
                    # server setup
                    mysql_config = {
                        'Image' => 'mysql:latest',
                        'name' => 'mysql_test',
                        'Env' => ['MYSQL_ALLOW_EMPTY_PASSWORD=yes', 'MYSQL_USER=test', 'MYSQL_DATABASE=testdb'],
                        'HostConfig' => {
                            'PortBindings' => {
                            '3306/tcp' => [{ 'HostPort' => '3307' }]
                            }
                        }
                    }
                    image = Docker::Image.create('fromImage' => 'mysql:latest')
                    image.refresh!
                    begin
                        Docker::Container.get('mysql_test').remove(force: true)
                    rescue
                    end
                    container = Docker::Container.create(mysql_config)
                    container.start
                    sleep 15
                    $event_list.clear()
                end

                def test_query
                    client = Mysql2::Client.new(:host => "127.0.0.1", :username => "root", :password => '', :database => 'testdb', :port => 3307)
                    client.query("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()

                    # CREATE event test 
                    client.query("create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))")
                    args = [{:sql=>"create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # INSERT event test 
                    client.query("INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com')")
                    args = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com')", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test 
                    client.query("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    args = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # SELECT event test 
                    # data verification 
                    results = client.query("SELECT * FROM fake_users WHERE name= 'john'", :symbolize_keys => true)
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {:name=>"john", :email=>"me@john.com", :grade=>"A", :blog=>"http://blog.abc.com"}
                    assert_equal expected_result, @output
                    # event verification
                    args = [{:sql=>"SELECT * FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test 
                    client.query("DELETE FROM fake_users WHERE name= 'john'") 
                    args = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # delete operation verify
                    @output = []
                    results = client.query("SELECT * FROM fake_users")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 

                    # DROP event test 
                    client.query("DROP TABLE fake_users") 
                    args = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    client.close()
                end

                def test_execute
                    client = Mysql2::Client.new(:host => "127.0.0.1", :username => "root", :password => '', :database => 'testdb', :port => 3307)
                    client.query("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()

                    # CREATE event test 
                    client.query("create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))")
                    args = [{:sql=>"create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50))", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # INSERT event test 
                    statement = client.prepare("INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)")
                    statement.execute("abc", "me@abc.com", "A", "http://blog.abc.com")
                    args = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", :parameters=>["abc", "me@abc.com", "A", "http://blog.abc.com"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test 
                    statement = client.prepare("UPDATE fake_users SET name = ?, email= ? WHERE name = ?")
                    statement.execute("john", "me@john.com", "abc")
                    args = [{:parameters=>["john", "me@john.com", "abc"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # SELECT event test 
                    # data verification 
                    statement = client.prepare("SELECT * FROM fake_users WHERE name = ?")
                    results = statement.execute('john')
                    results.each do |row|
                        @output = row
                    end
                    expected_result = {"name"=>"john", "email"=>"me@john.com", "grade"=>"A", "blog"=>"http://blog.abc.com"}
                    assert_equal expected_result, @output
                    # event verification
                    args = [{:parameters=>["john"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test 
                    statement = client.prepare("DELETE FROM fake_users WHERE name= ?") 
                    statement.execute("john")
                    args = [{:parameters=>["john"]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # delete operation verify
                    @output = []
                    results = client.query("SELECT * FROM fake_users")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 

                    # DROP event test 
                    client.query("DROP TABLE fake_users") 
                    args = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(@@case_type)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    client.close()
                end

                def teardown
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end

                Minitest.after_run do
                    # remove server
                    begin
                       Docker::Container.get('mysql_test').remove(force: true)
                    rescue
                    end
                end

            end
        end
    end
end
  