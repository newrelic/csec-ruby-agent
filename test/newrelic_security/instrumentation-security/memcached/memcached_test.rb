require 'dalli'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/memcached/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestMemcached < Minitest::Test
                @@before_all_flag = false
    
                def setup
                  $event_list.clear()
                  NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                  unless @@before_all_flag
                      NewRelic::Security::Test::DatabaseHelper.create_memcached_container
                      @@before_all_flag = true
                  end
                end

                def test_set_get_fetch_delete
                  cache = Dalli::Client.new("#{MEMCACHED_HOST}:#{MEMCACHED_PORT}")
                  $event_list.clear()
                  res = cache.set 'greet', 'hello', nil, :raw => true
                  args = [{:type=>:set, :arguments=>["greet", "hello", 0, 0, { :raw=>true }], :mode=>:write}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.get 'greet'
                  args = [{:type=>:get, :arguments=>["greet", nil], :mode=>:read}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 'hello', res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.fetch 'greet'
                  args = [{:type=>:get, :arguments=>["greet", nil], :mode=>:read}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 'hello', res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.delete 'greet'
                  args = [{:type=>:delete, :arguments=>["greet", 0], :mode=>:delete}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal true, res
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()
                end

                def test_set_incr_get_flush
                  cache = Dalli::Client.new("#{MEMCACHED_HOST}:#{MEMCACHED_PORT}")
                  $event_list.clear()
                  res = cache.set 'counter', 0, nil, :raw => true
                  args = [{:type=>:set, :arguments=>["counter", 0, 0, 0, {:raw=>true}], :mode=>:write}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.incr 'counter', 1
                  args = [{:type=>:incr, :arguments=>["counter", 1, 0, nil], :mode=>:update}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 1, res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.get 'counter'
                  args = [{:type=>:get, :arguments=>["counter", nil], :mode=>:read}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal "1", res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.decr 'counter', 1
                  args = [{:type=>:decr, :arguments=>["counter", 1, 0, nil], :mode=>:update}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, MEMCACHED)
                  assert_equal 0, res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
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
                    NewRelic::Security::Test::DatabaseHelper.remove_memcached_container
                end

            end
        end
    end
end
  