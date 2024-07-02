require 'redis'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/redis/instrumentation'

module NewRelic::Security
    module Test
        module Instrumentation
            class TestREDIS < Minitest::Test
                @@before_all_flag = false
    
                def setup
                  $event_list.clear()
                  NewRelic::Security::Agent::Control::HTTPContext.set_context({})
                  unless @@before_all_flag
                      NewRelic::Security::Test::DatabaseHelper.create_redis_container
                      @@before_all_flag = true
                  end
                end

                def test_set_get_fetch_delete
                  cache = Redis.new(host: REDIS_HOST)
                  $event_list.clear()
                  res = cache.set 'greet', 'hello'
                  args = [{:type=>:set, :arguments=>["greet", "hello"], :mode=>:write}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 'OK', res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.get 'greet'
                  args = [{:type=>:get, :arguments=>["greet"], :mode=>:read}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 'hello', res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.getdel 'greet'
                  args = [{:type=>:getdel, :arguments=>["greet"], :mode=>:delete}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal "hello", res
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()
                end

                def test_set_incr_get_flush
                  cache = Redis.new(host: REDIS_HOST)
                  $event_list.clear()
                  res = cache.set 'counter', 0
                  args = [{:type=>:set, :arguments=>["counter", "0"], :mode=>:write}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.incr 'counter'
                  args = [{:type=>:incr, :arguments=>["counter"], :mode=>:update}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 1, res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.get 'counter'
                  args = [{:type=>:get, :arguments=>["counter"], :mode=>:read}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal "1", res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.decr 'counter'
                  args = [{:type=>:decr, :arguments=>["counter"], :mode=>:update}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 0, res
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal expected_event.caseType, $event_list[0].caseType
                  assert_equal expected_event.parameters, $event_list[0].parameters
                  assert_equal expected_event.eventCategory, $event_list[0].eventCategory
                  $event_list.clear()

                  res = cache.del 'greet'
                  args = [{:type=>:del, :arguments=>["greet"], :mode=>:delete}]
                  expected_event = NewRelic::Security::Agent::Control::Event.new(CACHING_DATA_STORE, args, REDIS)
                  assert_equal 1, NewRelic::Security::Agent::Control::Collector.get_event_count(CACHING_DATA_STORE)
                  assert_equal 0, res
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
                    NewRelic::Security::Test::DatabaseHelper.remove_redis_container
                end

            end
        end
    end
end
  