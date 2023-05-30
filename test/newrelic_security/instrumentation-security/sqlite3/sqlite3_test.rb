require 'sqlite3'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/sqlite3/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestSqlite3 < Minitest::Test
                @@case_type = "SQL_DB_COMMAND"
                @@event_category = "SQLITE"
                @@database_name = __dir__ + "/test.db"

                def test_execute
                    db = SQLite3::Database.new @@database_name
                    db.execute("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()
                    # Create a table test
                    db.execute <<-SQL
                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); 
                    SQL
                    args1 = [{:sql=>"                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); \n", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # INSERT event test
                    db.execute("INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", ["abc", "me@abc.com", "A", "http://blog.abc.com"])
                    # puts @output.inspect
                    args2 = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", :parameters=>["abc", "me@abc.com", "A", "http://blog.abc.com"]}]
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event2.caseType, $event_list[0].caseType
                    assert_equal expected_event2.parameters, $event_list[0].parameters
                    assert_equal expected_event2.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test
                    db.execute("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    args3 = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event3.caseType, $event_list[0].caseType
                    assert_equal expected_event3.parameters, $event_list[0].parameters
                    assert_equal expected_event3.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # SELECT event test
                    @output = db.execute("SELECT * FROM fake_users WHERE name= 'john'")
                    expected_result = [["john", "me@john.com", "A", "http://blog.abc.com"]]
                    assert_equal expected_result, @output 
                    args4 = [{:sql=>"SELECT * FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event4 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args4, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event4.caseType, $event_list[0].caseType
                    assert_equal expected_event4.parameters, $event_list[0].parameters
                    assert_equal expected_event4.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test
                    db.execute("DELETE FROM fake_users WHERE name= 'john'")
                    args5 = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event5 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args5, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event5.caseType, $event_list[0].caseType
                    assert_equal expected_event5.parameters, $event_list[0].parameters
                    assert_equal expected_event5.eventCategory, $event_list[0].eventCategory
                    # verify delete operation
                    @output = db.execute("SELECT * FROM fake_users WHERE name= 'john'")
                    expected_result = []
                    assert_equal expected_result, @output 
                    # delete operation verify
                    @output = []
                    results = db.execute("SELECT * FROM fake_users")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 

                    # DROP table test
                    db.execute("DROP TABLE fake_users")
                    args6 = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event6 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args6, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event6.caseType, $event_list[0].caseType
                    assert_equal expected_event6.parameters, $event_list[0].parameters
                    assert_equal expected_event6.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                end

                def test_execute2
                    db = SQLite3::Database.new @@database_name
                    db.execute2("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()
                    # Create a table test
                    db.execute2 <<-SQL
                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); 
                    SQL
                    args1 = [{:sql=>"                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); \n", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # INSERT event test
                    db.execute2("INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", ["abc", "me@abc.com", "A", "http://blog.abc.com"])
                    args2 = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", :parameters=>["[\"abc\", \"me@abc.com\", \"A\", \"http://blog.abc.com\"]"]}]
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event2.caseType, $event_list[0].caseType
                    assert_equal expected_event2.parameters, $event_list[0].parameters
                    assert_equal expected_event2.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test
                    db.execute2("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'")
                    args4 = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'", :parameters=>[]}]
                    expected_event4 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args4, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event4.caseType, $event_list[0].caseType
                    assert_equal expected_event4.parameters, $event_list[0].parameters
                    assert_equal expected_event4.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
 
                    # SELECT event test
                    @output = db.execute2("SELECT * FROM fake_users WHERE name= 'john'")
                    expected_result = [["name", "email", "grade", "blog"], ["john", "me@john.com", "A", "http://blog.abc.com"]]
                    assert_equal expected_result, @output 
                    args3 = [{:sql=>"SELECT * FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event3.caseType, $event_list[0].caseType
                    assert_equal expected_event3.parameters, $event_list[0].parameters
                    assert_equal expected_event3.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test
                    db.execute2("DELETE FROM fake_users WHERE name= 'john'")
                    args5 = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'", :parameters=>[]}]
                    expected_event5 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args5, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event5.caseType, $event_list[0].caseType
                    assert_equal expected_event5.parameters, $event_list[0].parameters
                    assert_equal expected_event5.eventCategory, $event_list[0].eventCategory
                    # delete operation verify
                    @output = db.execute2("SELECT * FROM fake_users WHERE name= 'john'")
                    expected_result = [["name", "email", "grade", "blog"]]
                    assert_equal expected_result, @output 
                    $event_list.clear()

                    # DROP table test
                    db.execute2("DROP TABLE fake_users")
                    args6 = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event6 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args6, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event6.caseType, $event_list[0].caseType
                    assert_equal expected_event6.parameters, $event_list[0].parameters
                    assert_equal expected_event6.eventCategory, $event_list[0].eventCategory
                    $event_list.clear() 
                end

                def test_execute_batch
                    db = SQLite3::Database.new @@database_name
                    db.execute_batch("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()
                    
                    # Create a table test
                    db.execute_batch <<-SQL
                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); 
                    SQL
                    args1 = [{:sql=>"                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); \n", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # INSERT event test : 2 users entry 
                    db.execute_batch("INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com'); INSERT INTO fake_users (name, email, grade, blog) VALUES ('pqr', 'me@pqr.com', 'B', 'http://blog.pqr.com')")
                    args2 = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com'); INSERT INTO fake_users (name, email, grade, blog) VALUES ('pqr', 'me@pqr.com', 'B', 'http://blog.pqr.com')", :parameters=>[]}]
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event2.caseType, $event_list[0].caseType
                    assert_equal expected_event2.parameters, $event_list[0].parameters
                    assert_equal expected_event2.eventCategory, $event_list[0].eventCategory
                    # Inserted data verification
                    @output1 = db.execute("SELECT * FROM fake_users WHERE name= 'abc'")
                    expected_result1 = [["abc", "me@abc.com", "A", "http://blog.abc.com"]]
                    assert_equal expected_result1, @output1
                    @output2 = db.execute("SELECT * FROM fake_users WHERE name= 'pqr'")
                    expected_result2 = [["pqr", "me@pqr.com", "B", "http://blog.pqr.com"]]
                    assert_equal expected_result2, @output2
                    $event_list.clear()

                    # INSERT event test: using bind parameters
                    db.execute_batch("INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?); INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", ["xyz", "me@xyz.com", "C", "http://blog.xyz.com"])
                    args3 = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?); INSERT INTO fake_users (name, email, grade, blog) VALUES (?, ?, ?, ?)", :parameters=>["xyz", "me@xyz.com", "C", "http://blog.xyz.com"]}]
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event3.caseType, $event_list[0].caseType
                    assert_equal expected_event3.parameters, $event_list[0].parameters
                    assert_equal expected_event3.eventCategory, $event_list[0].eventCategory
                    # Inserted data verification
                    @output = db.execute("SELECT * FROM fake_users WHERE name= 'xyz'")
                    expected_result = [["xyz", "me@xyz.com", "C", "http://blog.xyz.com"], ["xyz", "me@xyz.com", "C", "http://blog.xyz.com"]]
                    assert_equal expected_result, @output
                    $event_list.clear()

                    # UPDATE event test
                    db.execute_batch("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'; UPDATE fake_users SET name = 'jack', email= 'me@jack.com' WHERE name = 'pqr'")
                    args4 = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'; UPDATE fake_users SET name = 'jack', email= 'me@jack.com' WHERE name = 'pqr'", :parameters=>[]}]
                    expected_event4 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args4, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event4.caseType, $event_list[0].caseType
                    assert_equal expected_event4.parameters, $event_list[0].parameters
                    assert_equal expected_event4.eventCategory, $event_list[0].eventCategory
                    # Updated data verification
                    @output1 = db.execute("SELECT * FROM fake_users WHERE name= 'john'")
                    expected_result1 = [["john", "me@john.com", "A", "http://blog.abc.com"]]
                    assert_equal expected_result1, @output1
                    @output2 = db.execute("SELECT * FROM fake_users WHERE name= 'jack'")
                    expected_result2 = [["jack", "me@jack.com", "B", "http://blog.pqr.com"]]
                    assert_equal expected_result2, @output2
                    $event_list.clear()

                    # DELETE event test
                    db.execute_batch("DELETE FROM fake_users WHERE name= 'john'; DELETE FROM fake_users WHERE name= 'jack'")
                    args5 = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'; DELETE FROM fake_users WHERE name= 'jack'", :parameters=>[]}]
                    expected_event5 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args5, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event5.caseType, $event_list[0].caseType
                    assert_equal expected_event5.parameters, $event_list[0].parameters
                    assert_equal expected_event5.eventCategory, $event_list[0].eventCategory
                    # delete operation verify
                    @output = []
                    results = db.execute("SELECT * FROM fake_users WHERE name= 'john' or name= 'jack'")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 

                    # DROP table test
                    db.execute_batch("DROP TABLE fake_users")
                    args6 = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event6 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args6, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event6.caseType, $event_list[0].caseType
                    assert_equal expected_event6.parameters, $event_list[0].parameters
                    assert_equal expected_event6.eventCategory, $event_list[0].eventCategory
                    $event_list.clear() 
                end

                def test_execute_batch2
                    db = SQLite3::Database.new @@database_name
                    db.execute_batch2("DROP TABLE IF EXISTS fake_users")
                    $event_list.clear()
                    
                    # Create a table test
                    db.execute_batch2 <<-SQL
                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); 
                    SQL
                    args1 = [{:sql=>"                    create table fake_users ( name varchar(50), email varchar(50), grade varchar(5), blog varchar(50)); \n", :parameters=>[]}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args1, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # INSERT event test : 2 users entry 
                    db.execute_batch2("INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com'); INSERT INTO fake_users (name, email, grade, blog) VALUES ('pqr', 'me@pqr.com', 'B', 'http://blog.pqr.com')")
                    args2 = [{:sql=>"INSERT INTO fake_users (name, email, grade, blog) VALUES ('abc', 'me@abc.com', 'A', 'http://blog.abc.com'); INSERT INTO fake_users (name, email, grade, blog) VALUES ('pqr', 'me@pqr.com', 'B', 'http://blog.pqr.com')", :parameters=>[]}]
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event2.caseType, $event_list[0].caseType
                    assert_equal expected_event2.parameters, $event_list[0].parameters
                    assert_equal expected_event2.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # UPDATE event test
                    db.execute_batch2("UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'; UPDATE fake_users SET name = 'jack', email= 'me@jack.com' WHERE name = 'pqr'")
                    args3 = [{:sql=>"UPDATE fake_users SET name = 'john', email= 'me@john.com' WHERE name = 'abc'; UPDATE fake_users SET name = 'jack', email= 'me@jack.com' WHERE name = 'pqr'", :parameters=>[]}]
                    expected_event3 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args3, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event3.caseType, $event_list[0].caseType
                    assert_equal expected_event3.parameters, $event_list[0].parameters
                    assert_equal expected_event3.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # SELECT event test
                    # data verification
                    @output = db.execute_batch2("SELECT * FROM fake_users WHERE name= 'john'; SELECT * FROM fake_users WHERE name= 'jack'")
                    expected_result = [["john", "me@john.com", "A", "http://blog.abc.com"], ["jack", "me@jack.com", "B", "http://blog.pqr.com"]]
                    assert_equal expected_result, @output
                    # event verification
                    args4 = [{:sql=>"SELECT * FROM fake_users WHERE name= 'john'; SELECT * FROM fake_users WHERE name= 'jack'", :parameters=>[]}]
                    expected_event4 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args4, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event4.caseType, $event_list[0].caseType
                    assert_equal expected_event4.parameters, $event_list[0].parameters
                    assert_equal expected_event4.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # DELETE event test
                    db.execute_batch2("DELETE FROM fake_users WHERE name= 'john'; DELETE FROM fake_users WHERE name= 'jack'")
                    args5 = [{:sql=>"DELETE FROM fake_users WHERE name= 'john'; DELETE FROM fake_users WHERE name= 'jack'", :parameters=>[]}]
                    expected_event5 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args5, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event5.caseType, $event_list[0].caseType
                    assert_equal expected_event5.parameters, $event_list[0].parameters
                    assert_equal expected_event5.eventCategory, $event_list[0].eventCategory
                    # delete operation verify
                    @output = []
                    results = db.execute("SELECT * FROM fake_users WHERE name= 'john' or name= 'jack'")
                    results.each do |row|
                        @output.push(row)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear() 

                    # DROP table test
                    db.execute_batch2("DROP TABLE fake_users")
                    args6 = [{:sql=>"DROP TABLE fake_users", :parameters=>[]}]
                    expected_event6 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args6, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event6.caseType, $event_list[0].caseType
                    assert_equal expected_event6.parameters, $event_list[0].parameters
                    assert_equal expected_event6.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                end

            end
        end
    end
end
