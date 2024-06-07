require 'rails'
require 'sqlite3'
require 'active_record'
require_relative '../../../../test_helper'
require 'newrelic_security/instrumentation-security/sqlite3/instrumentation'

class FakeUser < ActiveRecord::Base
end

# test setup
$database_name = __dir__ + "/db/test.db"
ActiveRecord::Base.establish_connection adapter: 'sqlite3', database: $database_name
load  "#{__dir__}/db/schema.rb"

require 'newrelic_security/instrumentation-security//active_record/sqlite3_adapter/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestSQLite3Adapter < Minitest::Test

                def setup
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                end

                def test_exec_query
                    ActiveRecord::Base.establish_connection adapter: 'sqlite3', database: $database_name
                    FakeUser.delete_all
                    $event_list.clear()

                    # INSERT test
                    if RUBY_VERSION <= '2.5.0'
                        FakeUser.create(id: 1, email: 'me@john.com', name: 'John', ssn: '11')
                        # 4 event verify
                        args1 = [{:sql=>"            SELECT sql FROM\n              (SELECT * FROM sqlite_master UNION ALL\n               SELECT * FROM sqlite_temp_master)\n            WHERE type = 'table' AND name = 'fake_users'\n", :parameters=>[]}]
                        args2 = [{:sql=>"SELECT name FROM sqlite_master WHERE name <> 'sqlite_sequence' AND type IN ('table','view')", :parameters=>[]}]
                        args3 = [{:sql=>"INSERT INTO \"fake_users\" (\"id\", \"name\", \"email\", \"ssn\") VALUES (?, ?, ?, ?)", :parameters=>["1", "John", "me@john.com", "11"]}]
                        expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, SQLITE)
                        expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, SQLITE)
                        expected_event3 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args3, SQLITE)
                        assert_equal 4, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                        # sqlite_master
                        assert_equal expected_event1.caseType, $event_list[0].caseType
                        assert_equal expected_event1.parameters, $event_list[0].parameters
                        assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                        # sqlite_sequence
                        assert_equal expected_event2.caseType, $event_list[1].caseType
                        assert_equal expected_event2.parameters, $event_list[1].parameters
                        assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                        # sqlite_master
                        assert_equal expected_event1.caseType, $event_list[2].caseType
                        assert_equal expected_event1.parameters, $event_list[2].parameters
                        assert_equal expected_event1.eventCategory, $event_list[2].eventCategory
                        # insert
                        assert_equal expected_event3.caseType, $event_list[3].caseType
                        assert_equal expected_event3.parameters, $event_list[3].parameters
                        assert_equal expected_event3.eventCategory, $event_list[3].eventCategory
                    else
                        FakeUser.insert(
                            { id: 1,
                            email: 'me@john.com',
                            name: 'John',
                            ssn: '11' }
                        )
                        # 3 event verify
                        args1 = [{:sql=>"SELECT sqlite_version(*)", :parameters=>[]}]
                        args2 = [{:sql=>"SELECT sql FROM\n  (SELECT * FROM sqlite_master UNION ALL\n   SELECT * FROM sqlite_temp_master)\nWHERE type = 'table' AND name = 'fake_users'\n", :parameters=>[]}]
                        args3 = [{:sql=>"INSERT INTO \"fake_users\" (\"id\",\"email\",\"name\",\"ssn\") VALUES (1, 'me@john.com', 'John', '11') ON CONFLICT  DO NOTHING", :parameters=>[]}]
                        expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, SQLITE)
                        expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, SQLITE)
                        expected_event3 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args3, SQLITE)
                        assert_equal 3, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                        # sqlite_version
                        assert_equal expected_event1.caseType, $event_list[0].caseType
                        assert_equal expected_event1.parameters, $event_list[0].parameters
                        assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                        # sqlite_master
                        assert_equal expected_event2.caseType, $event_list[1].caseType
                        assert_equal expected_event2.parameters, $event_list[1].parameters
                        assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                        # insert
                        assert_equal expected_event3.caseType, $event_list[2].caseType
                        assert_equal expected_event3.parameters, $event_list[2].parameters
                        assert_equal expected_event3.eventCategory, $event_list[2].eventCategory
                    end
                    $event_list.clear()

                    # SELECT test
                    output = FakeUser.find(1)
                    # data verify
                    assert_equal 1, output.id
                    assert_equal "John", output.name
                    assert_equal "me@john.com", output.email
                    assert_equal "11", output.ssn
                    # event verify
                    args1 = [{:sql=>"SELECT \"fake_users\".* FROM \"fake_users\" WHERE \"fake_users\".\"id\" = ? LIMIT ?", :parameters=>["1", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, SQLITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    expected_sql_list = args1[0][:sql].split(" ")
                    sql_fetch_list = $event_list[0].parameters[0][:sql].split(" ")
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_sql_list, sql_fetch_list
                    assert_equal expected_event1.parameters[0][:parameters], $event_list[0].parameters[0][:parameters]
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE test
                    output = FakeUser.update(1, name: "Jack")
                    # data verify
                    assert_equal 1, output.id
                    assert_equal "Jack", output.name
                    assert_equal "me@john.com", output.email
                    assert_equal "11", output.ssn
                    # event verify
                    args1 = [{:sql=>"SELECT \"fake_users\".* FROM \"fake_users\" WHERE \"fake_users\".\"id\" = ? LIMIT ?", :parameters=>["1", "1"]}]
                    args2 = [{:sql=>"UPDATE \"fake_users\" SET \"name\" = ? WHERE \"fake_users\".\"id\" = ?", :parameters=>["Jack", "1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, SQLITE)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args2, SQLITE)
                    assert_equal 2, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    # select event
                    expected_sql_list = args1[0][:sql].split(" ")
                    sql_fetch_list = $event_list[0].parameters[0][:sql].split(" ")
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_sql_list, sql_fetch_list
                    assert_equal expected_event1.parameters[0][:parameters], $event_list[0].parameters[0][:parameters]
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    # update event
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    $event_list.clear()

                    # DELETE test
                    output = FakeUser.delete(1)
                    # data verify
                    assert_equal 1, output
                    # event verify
                    args1 = [{:sql=>"DELETE FROM \"fake_users\" WHERE \"fake_users\".\"id\" = ?", :parameters=>["1"]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(SQL_DB_COMMAND, args1, SQLITE)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(SQL_DB_COMMAND)
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    ActiveRecord::Base.remove_connection
                    $event_list.clear()
                end

                def teardown
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end

            end
        end
    end
end

