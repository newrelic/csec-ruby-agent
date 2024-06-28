require 'elasticsearch'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/elasticsearch/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestElasticsearch < Minitest::Test
                @@before_all_flag = false
    
                def setup
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                    unless @@before_all_flag
                        NewRelic::Security::Test::DatabaseHelper.create_elasticsearch_container
                        @@before_all_flag = true
                    end
                end

                def test_index
                    client = Elasticsearch::Client.new(url: "http://#{ELASTICSEARCH_HOST}:#{ELASTICSEARCH_PORT}", request_timeout: 30)

                    client.index(index: 'blind', body: {:key => :value})
                    $event_list.clear()
                    document = { title: 'Sample Document', content: 'This is a sample document' }
                    index_response = client.index(index: 'my_index', body: document)
                    doc_id = index_response['_id']
                    args = [{:method=>"POST", :path=>"my_index/_doc", :params=>{}, :body=>"{\"title\":\"Sample Document\",\"content\":\"This is a sample document\"}", :headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(NOSQL_DB_COMMAND, args, ES)
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(NOSQL_DB_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    get_response = client.get(index: 'my_index', id: doc_id)
                    args = [{:method=>"GET", :path=>"my_index/_doc/#{doc_id}", :params=>{}, :body=>"null", :headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(NOSQL_DB_COMMAND, args, ES)
                    assert_equal document[:title], get_response['_source']["title"]
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(NOSQL_DB_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    update_document = { title: 'Updated Document', content: 'This is an updated document' }
                    update_response = client.update(index:'my_index', id: doc_id, body: { doc: document })
                    args = [{:method=>"POST", :path=>"my_index/_update/#{doc_id}", :params=>{}, :body=>"{\"doc\":{\"title\":\"Sample Document\",\"content\":\"This is a sample document\"}}", :headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(NOSQL_DB_COMMAND, args, ES)
                    assert_equal doc_id, update_response['_id']
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(NOSQL_DB_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()

                    delete_response = client.delete(index: 'my_index', id: doc_id)
                    args = [{:method=>"DELETE", :path=>"my_index/_doc/#{doc_id}", :params=>{}, :body=>"null", :headers=>{}}]
                    expected_event = NewRelic::Security::Agent::Control::Event.new(NOSQL_DB_COMMAND, args, ES)
                    assert_equal doc_id, delete_response['_id']
                    assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(NOSQL_DB_COMMAND)
                    assert_equal expected_event.caseType, $event_list[0].caseType
                    assert_equal expected_event.parameters, $event_list[0].parameters
                    assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                    $event_list.clear()
                end

                def teardown
                    $event_list.clear()
                    NewRelic::Security::Agent::Control::HTTPContext.reset_context
                end

                Minitest.after_run do
                    NewRelic::Security::Test::DatabaseHelper.remove_elasticsearch_container
                end

            end
        end
    end
end
  