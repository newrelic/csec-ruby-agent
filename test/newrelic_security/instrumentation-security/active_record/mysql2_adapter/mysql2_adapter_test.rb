require 'rails'
require 'active_record'
require "active_record/connection_adapters/mysql2_adapter"
require_relative '../../../../test_helper'
require 'newrelic_security/instrumentation-security/active_record/mysql2_adapter/instrumentation'

class NewUser < ActiveRecord::Base
end

module NewRelic::Security
    module Test
        module Instrumentation
            class TestMysql2Adapter < Minitest::Test
                @@before_all_flag = false

                def setup
                    $event_list.clear()
                    unless @@before_all_flag
                        NewRelic::Security::Test::DatabaseHelper.create_mysql_container
                        @@before_all_flag = true
                    end
                end

                def test_exec_query_exec_insert_exec_update
                    ActiveRecord::Base.establish_connection adapter: 'jdbcmysql', database: MYSQL_DATABASE, :port => MYSQL_PORT, :host => MYSQL_HOST, :user => MYSQL_USERNAME
                    load  __dir__ + '/db/schema.rb'
                    NewUser.delete_all
                    $event_list.clear()

                    # INSERT test
                    if RUBY_VERSION < '2.5.0'
                        NewUser.create(id: 1, email: 'me@john.com', name: 'John', ssn: '11')
                        # event verify
                        args1 = [{:sql=>"INSERT INTO \"new_users\" (\"id\", \"name\", \"email\", \"ssn\") VALUES ($1, $2, $3, $4) RETURNING \"id\"", :parameters=>["1", "John", "me@john.com", "11"]}]
                        expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)

                        assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                        # insert event
                        assert_equal expected_event1.caseType, $event_list[0].caseType
                        assert_equal expected_event1.parameters, $event_list[0].parameters
                        assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    else
                        NewUser.insert({ id: 1, email: 'me@john.com', name: 'John', ssn: '11' })
                        # insert event
                        args1 = [{:sql=>"SHOW FULL FIELDS FROM `new_users`", :parameters=>[]}]
                        args2 = [{:sql=>"INSERT INTO `new_users` (`id`,`email`,`name`,`ssn`) VALUES (1, 'me@john.com', 'John', '11') ON DUPLICATE KEY UPDATE `id`=`id`", :parameters=>[]}]
                        expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)
                        expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, MYSQL)

                        assert_equal 2, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                        assert_equal expected_event1.caseType, $event_list[0].caseType
                        assert_equal expected_event1.parameters, $event_list[0].parameters
                        assert_equal expected_event1.eventCategory, $event_list[0].eventCategory

                        assert_equal expected_event2.caseType, $event_list[1].caseType
                        assert_equal expected_event2.parameters, $event_list[1].parameters
                        assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    end
                    $event_list.clear()

                    # SELECT test
                    output = NewUser.find(1)
                    # data verify
                    assert_equal 1, output.id
                    assert_equal "John", output.name
                    assert_equal "me@john.com", output.email
                    assert_equal "11", output.ssn
                    # event verify
                    args1 = [{:sql=>"SELECT `new_users`.* FROM `new_users` WHERE `new_users`.`id` = 1 LIMIT 1", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)

                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters[0], $event_list[0].parameters[0]
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE test
                    output = NewUser.update(1, name: "Jack")
                    # data verify
                    assert_equal 1, output.id
                    assert_equal "Jack", output.name
                    assert_equal "me@john.com", output.email
                    assert_equal "11", output.ssn
                    # exec_update event verify
                    args1 = [{:sql=>"SELECT `new_users`.* FROM `new_users` WHERE `new_users`.`id` = 1 LIMIT 1", :parameters=>[]}]
                    args2 = [{:sql=>"UPDATE `new_users` SET `new_users`.`name` = 'Jack' WHERE `new_users`.`id` = 1", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, MYSQL)

                    assert_equal 2, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    # select event
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    # update event
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    $event_list.clear()

                    # DELETE test
                    skip("Issue in delete case in jruby") if RUBY_ENGINE == 'jruby'
                    output = NewUser.delete(1)
                    # data verify
                    assert_equal 1, output
                    # event verify
                    args1 = [{:sql=>"DELETE FROM \"new_users\" WHERE \"new_users\".\"id\" = $1", :parameters=>["1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)

                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()
                end

                def test_execute
                    ActiveRecord::Base.establish_connection adapter: 'mysql2', database: MYSQL_DATABASE, :port => MYSQL_PORT, :host => MYSQL_HOST, :user => MYSQL_USERNAME
                    load  __dir__ + '/db/schema.rb'
                    NewUser.delete_all

                    # INSERT test
                    $event_list.clear()
                    ActiveRecord::Base.connection.execute("INSERT INTO new_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')")
                    # execute event verify
                    args1 = [{:sql=>"INSERT INTO new_users (id, email, name, ssn) VALUES (1, 'me@abc.com', 'John', '11')", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE test
                    ActiveRecord::Base.connection.execute("UPDATE new_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    # execute event verify
                    args1 = [{:sql=>"UPDATE new_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)
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
                    if ::Rails.version < '5'
                        expected_result = {"id"=>"1", "name"=>"John", "email"=>"me@abc.com", "ssn"=>"11"}
                    else
                        expected_result = {"id"=>1, "name"=>"John", "email"=>"me@abc.com", "ssn"=>"11"}
                    end
                    assert_equal expected_result, output
                    # event verification
                    args = [{:sql=>"SELECT * FROM new_users", :parameters=>[]}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args, MYSQL)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE test
                    ActiveRecord::Base.connection.execute("DELETE FROM new_users WHERE name= 'john'")
                    # execute event verify
                    args1 = [{:sql=>"DELETE FROM new_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, MYSQL)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()
                end

                Minitest.after_run do
                    NewRelic::Security::Test::DatabaseHelper.remove_mysql_container
                end

            end
        end
    end
end
