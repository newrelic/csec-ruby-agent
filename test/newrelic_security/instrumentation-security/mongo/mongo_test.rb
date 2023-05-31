require 'mongo'
require 'testcontainers'
require 'json'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/mongo/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestMongo < Minitest::Test
                @@case_type = "NOSQL_DB_COMMAND"
                @@event_category = "MONGO"
                
                def test_insert_one_update_one_delete_one_find
                    # server setup
                    container = Testcontainers::DockerContainer.new("mongo:latest")
                    container.name = "mongo_test"
                    container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                    begin
                        `docker rm -f mongo_test`
                    rescue
                    end
                    container.start
                    sleep 5

                    client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                    client[:cars].find.each do |document|
                        client[:cars].delete_one( document )
                    end
                    $event_list.clear()

                    # insert_one test
                    value = '{"name":"abc", "price":"5000"}'
                    @output = client[:cars].insert_one(JSON.parse(value))
                    # insert count
                    assert_equal 1, @output.n         
                    args = [{:payload=>{:document=>{"name"=>"abc", "price"=>"5000"}, :opts=>{}}, :payloadType=>:insert}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    # event count and output data verify
                    # assert_equal 1, $event_list.length       
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # update_one test
                    old_value = '{"name":"abc"}'
                    new_value = '{"name":"pqr"}'
                    new_value_change = '{"$set":'+new_value+'}'
                    @output = client[:cars].update_one(JSON.parse(old_value), JSON.parse(new_value_change) )
                    # update count
                    assert_equal 1, @output.modified_count      
                    args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set"=>{"name"=>"pqr"}}, :options=>{}}, :payloadType=>:update}]
                    args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    assert_equal 2, $event_list.length
                    # update event verify
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # find event verify
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    $event_list.clear()

                    # find test
                    @output = client[:cars].find( JSON.parse(new_value) ).first
                    # output data verify
                    assert_equal 3, @output.length
                    assert_equal "pqr", @output["name"]
                    assert_equal "5000", @output["price"]
                    args = [{:payload=>{:filter=>{"name"=>"pqr"}, :options=>{}}, :payloadType=>:find}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length 
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # delete_one test
                    result = client[:cars].delete_one( JSON.parse(new_value) )
                    @output = result.deleted_count
                    assert_equal 1, @output
                    args = [{:payload=>{:filter=>{"name"=>"pqr"}, :options=>{}}, :payloadType=>:delete}]
                    args2 = [{:payload=>{:filter=>{"name"=>"pqr"}, :options=>{}}, :payloadType=>:find}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    assert_equal 2, $event_list.length # event count
                    # delete event
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    # find event
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    # delete operation verify
                    @output = []
                    client[:cars].find.each do |document|
                        @output.push(document)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear()
                    client.close()
                    # remove server
                    container.stop
                    container.delete
                end
                
                def test_insert_many_update_many_delete_many
                    # server setup
                    container = Testcontainers::DockerContainer.new("mongo:latest")
                    container.name = "mongo_test"
                    container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                    begin
                        `docker rm -f mongo_test`
                    rescue
                    end
                    container.start
                    sleep 5

                    client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                    client[:cars].find.each do |document|
                        client[:cars].delete_one( document )
                    end
                    $event_list.clear()

                    # insert many test
                    docs = [ { _id: 1, name: 'abc', price: '5000' }, { _id: 2, name: 'pqr', price: '1000' } ]
                    result = client[:cars].insert_many(docs)
                    # insert count
                    @output = result.inserted_count
                    assert_equal 2, @output     
                    # event verify    
                    args = [{:payload=>{:documents=>[{:_id=>1, :name=>"abc", :price=>"5000"}, {:_id=>2, :name=>"pqr", :price=>"1000"}], :options=>{}}, :payloadType=>:insert}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    # assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    
                    # update many test
                    @output = client[:cars].update_many( {}, { "$set" => { :price =>  "2000" } } )
                    # modify count
                    assert_equal 2, @output.modified_count  
                    args = [{:payload=>{:filter=>{}, :update=>{"$set"=>{:price=>"2000"}}, :options=>{}}, :payloadType=>:update}]
                    args2 = [{:payload=>{:filter=>{}, :options=>{}}, :payloadType=>:find}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    # update_many event verify
                    assert_equal 2, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    # find event verify
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    $event_list.clear()
                    
                    # find.each test
                    @output = []
                    client[:cars].find.each do |document|
                        @output.push(document["_id"], document["name"], document["price"])
                    end
                    # output data verify
                    assert_equal 6, @output.length
                    assert_equal [1, "abc", "2000"], [@output[0], @output[1], @output[2]]
                    assert_equal [2, "pqr", "2000"], [@output[3], @output[4], @output[5]]
                    # event verify
                    args = [{:payload=>{:filter=>nil, :options=>{}}, :payloadType=>:find}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    assert_equal 1, $event_list.length
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    # delete many test
                    @output = client[:cars].delete_many(:price => '2000')
                    assert_equal 2, @output.n
                    args = [{:payload=>{:filter=>{:price=>"2000"}, :options=>{}}, :payloadType=>:delete}]
                    args2 = [{:payload=>{:filter=>{:price=>"2000"}, :options=>{}}, :payloadType=>:find}]
                    expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                    # delete_many event verify
                    assert_equal 2, $event_list.length
                    assert_equal expected_event1.caseType, $event_list[0].caseType
                    assert_equal expected_event1.parameters, $event_list[0].parameters
                    assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                    # find event verify
                    assert_equal expected_event2.caseType, $event_list[1].caseType
                    assert_equal expected_event2.parameters, $event_list[1].parameters
                    assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    # delete operation verify
                    @output = []
                    client[:cars].find.each do |document|
                        @output.push(document)
                    end
                    assert_equal 0, @output.length
                    $event_list.clear()
                    client.close()
                    # remove server
                    container.stop
                    container.delete
                end

                def test_insert_one_QueryCache_enabled
                    # server setup
                    container = Testcontainers::DockerContainer.new("mongo:latest")
                    container.name = "mongo_test"
                    container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                    begin
                        `docker rm -f mongo_test`
                    rescue
                    end
                    container.start
                    sleep 5
                    client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                    client[:cars].find.each do |document|
                        client[:cars].delete_one( document )
                    end
                    $event_list.clear()
                    
                    # insert_one test   using Mongo::QueryCache.enabled = true
                    value = '{"name":"abc", "price":"5000"}'
                    Mongo::QueryCache.cache do
                        @output = client[:cars].insert_one(JSON.parse(value))
                    end  
                    assert_equal 1, @output.n        
                    #event verify    
                    args = [{:payload=>{:document=>{"name"=>"abc", "price"=>"5000"}, :opts=>{}}, :payloadType=>:insert}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                    # event count and output data verify
                    # assert_equal 1, $event_list.length       
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                    @output = client[:cars].find( JSON.parse(value) ).first
                    # output data verify
                    assert_equal 3, @output.length
                    assert_equal "abc", @output["name"]
                    assert_equal "5000", @output["price"]
                    $event_list.clear()
                    client.close()
                    # remove server
                    container.stop
                    container.delete
                end 

                # def test_find_update_one
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # find.update_one test        
                #     # Issue: event created only for find but not for update_one
                #     new_value = '{"name":"pqr"}'
                #     new_value_change = '{"$set":'+new_value+'}'
                #     @output = client[:cars].find(:name => 'abc').update_one(JSON.parse(new_value_change))
                #     puts @output.inspect
                #     # update count
                #     assert_equal 1, @output.modified_count 
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set" => { :name => "pqr" }}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # update event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                #     # output data verify
                #     @output = client[:cars].find( JSON.parse(new_value) ).first
                #     assert_equal 3, @output.length
                #     assert_equal "pqr", @output["name"]
                #     assert_equal "5000", @output["price"]
                #     $event_list.clear()
                #     client.close()
                #     puts "done"
                #     # remove server
                #     container.stop
                #     container.delete
                # end 

                # def test_find_delete_one
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find.delete_one test        
                #     @output = client[:cars].find(:name => 'abc').delete_one
                #     puts @output.inspect
                #     # delete count
                #     assert_equal 1, @output.n
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set" => { :name => "pqr" }}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # delete event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                    
                #     # delete operation verify
                #     @output = []
                #     client[:cars].find.each do |document|
                #         @output.push(document)
                #     end
                #     assert_equal 0, @output.length
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end 

                # def test_find_one_and_delete
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "Documents:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find_one_and_delete test       
                #     @output = client[:cars].find(:name => 'abc').find_one_and_delete
                #     assert_equal "abc", @output["name"]
                #     assert_equal "5000", @output["price"]
                #     # assert_equal 1, @output
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:delete}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # delete event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory

                #     # # Show all documents
                #     # puts "Documents:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end 

                # def test_find_update_many
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     docs = [ { _id: 1, name: 'abc', price: '1000' }, { _id: 2, name: 'pqr', price: '1000' } ]
                #     result = client[:cars].insert_many(docs)
                #     @output = result.inserted_count
                #     assert_equal 2, @output     # insert count   
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "Documents:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find.update_many test      
                #     @output = client[:cars].find(:price => '1000').update_many({ "$set" => { :price =>  '4000' } })
                #     # modify count
                #     # assert_equal 2, @output.modified_count  
                #     args = [{:payload=>{:filter=>{}, :update=>{"$set"=>{:price=>"4000"}}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{}, :options=>{}}, :payloadType=>:find}]
                #     expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     # update_many event verify
                #     assert_equal 2, $event_list.length
                #     assert_equal expected_event1.caseType, $event_list[0].caseType
                #     assert_equal expected_event1.parameters, $event_list[0].parameters
                #     assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory

                #     # # Show all documents
                #     # puts "Documents:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end

                # def test_find_delete_many
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.env = ['POSTGRES_HOST_AUTH_METHOD=trust']
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     docs = [ { _id: 1, name: 'abc', price: '1000' }, { _id: 2, name: 'pqr', price: '1000' } ]
                #     result = client[:cars].insert_many(docs)
                #     @output = result.inserted_count
                #     assert_equal 2, @output     # insert count   
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "Documents:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find.delete_many test      
                #     @output = client[:cars].find(:price => '1000').delete_many
                #     # delete count
                #     assert_equal 2, @output.deleted_count  
                #     # event verify
                #     args = [{:payload=>{:filter=>{}, :update=>{"$set"=>{:price=>"1000"}}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{}, :options=>{}}, :payloadType=>:find}]
                #     expected_event1 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     # update_many event verify
                #     assert_equal 2, $event_list.length
                #     assert_equal expected_event1.caseType, $event_list[0].caseType
                #     assert_equal expected_event1.parameters, $event_list[0].parameters
                #     assert_equal expected_event1.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory

                #     # delete operation verify
                #     @output = []
                #     client[:cars].find.each do |document|
                #         @output.push(document)
                #     end
                #     assert_equal 0, @output.length
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end

                # def test_replace_one
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # replace_one test        
                #     @output = client[:cars].replace_one( { :name => 'abc' }, { :name => 'pqr' } )
                #     puts @output.inspect
                #     # update count
                #     assert_equal 1, @output.modified_count 
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set" => { :name => "pqr" }}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # update event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                #     # output data verify
                #     @output = client[:cars].find( { :name => "pqr" } ).first
                #     assert_equal 2, @output.length
                #     assert_equal "pqr", @output["name"]
                    
                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end 

                # def test_find_replace_one
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find.replace_one test        
                #     @output = client[:cars].find(:name => 'abc').replace_one(:name => 'pqr')
                #     puts @output.inspect
                #     # update count
                #     assert_equal 1, @output.modified_count 
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set" => { :name => "pqr" }}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # update event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                #     # output data verify
                #     @output = client[:cars].find( { :name => "pqr" } ).first
                #     assert_equal 2, @output.length
                #     assert_equal "pqr", @output["name"]
                    
                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end 

                # def test_find_one_and_replace
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find_one_and_replace test        
                #     @output = client[:cars].find(:name => 'abc').find_one_and_replace(:name => 'pqr')
                #     assert_equal "abc", @output["name"]
                #     assert_equal "5000", @output["price"]
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set" => { :name => "pqr" }}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # update event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                #     # output data verify
                #     @output = client[:cars].find( { :name => "pqr" } ).first
                #     assert_equal 2, @output.length
                #     assert_equal "pqr", @output["name"]
                    
                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end 

                # def test_find_one_and_update
                #     # server setup
                #     container = Testcontainers::DockerContainer.new("mongo:latest")
                #     container.name = "mongo_test"
                #     container.port_bindings = {"27017/tcp"=>[{"HostPort"=>"27018"}]}
                #     begin
                #         `docker rm -f mongo_test`
                #     rescue
                #     end
                #     container.start
                #     sleep 5
                #     client = Mongo::Client.new(['localhost:27018'], :database => 'testdb')
                #     client[:cars].find.each do |document|
                #         client[:cars].delete_one( document )
                #     end
                #     value = '{"name":"abc", "price":"5000"}'
                #     @output = client[:cars].insert_one(JSON.parse(value))
                #     assert_equal 1, @output.n         
                #     $event_list.clear()

                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     # $event_list.clear()

                #     # find_one_and_update test        
                #     @output = client[:cars].find(:name => 'abc').find_one_and_update( '$set' => { :name => 'pqr' } )
                #     assert_equal "abc", @output["name"]
                #     assert_equal "5000", @output["price"]
                #     # event verify     
                #     args = [{:payload=>{:filter=>{"name"=>"abc"}, :update=>{"$set" => { :name => "pqr" }}, :options=>{}}, :payloadType=>:update}]
                #     args2 = [{:payload=>{:filter=>{"name"=>"abc"}, :options=>{}}, :payloadType=>:find}]
                #     expected_event = NewRelic::Security::Agent::Control::Event.new(@@case_type, args, @@event_category)
                #     expected_event2 = NewRelic::Security::Agent::Control::Event.new(@@case_type, args2, @@event_category)
                #     puts $event_list[0].caseType, $event_list[0].parameters, $event_list[0].eventCategory 
                #     assert_equal 2, $event_list.length
                #     # update event verify
                #     assert_equal expected_event.caseType, $event_list[0].caseType
                #     assert_equal expected_event.parameters, $event_list[0].parameters
                #     assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                #     # find event verify
                #     assert_equal expected_event2.caseType, $event_list[1].caseType
                #     assert_equal expected_event2.parameters, $event_list[1].parameters
                #     assert_equal expected_event2.eventCategory, $event_list[1].eventCategory
                #     # output data verify
                #     @output = client[:cars].find( { :name => "pqr" } ).first
                #     assert_equal 3, @output.length
                #     assert_equal "pqr", @output["name"]
                #     assert_equal "5000", @output["price"]

                #     # # Show all documents
                #     # puts "\nDocuments:"
                #     # client[:cars].find.each do |document|
                #     #     puts document
                #     # end
                #     $event_list.clear()
                #     client.close()
                #     # remove server
                #     container.stop
                #     container.delete
                # end 
            end
        end
    end
end