require 'rails'
require 'action_controller/railtie'
require 'rack/test'
require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/rails/instrumentation'

class MyApp < Rails::Application
  config.active_support.deprecation = :log
  config.eager_load = false
  config.filter_parameters += [:secret]
  if Rails::VERSION::STRING >= '7.0.0'
    config.action_controller.default_protect_from_forgery = true
  end
  if config.respond_to?(:hosts)
    config.hosts << 'www.example.com'
  end
end

MyApp.initialize!

MyApp.routes.draw do

  get '/myapi', :to => 'myapi#fetch'
  post '/myapi2', :to => 'myapi#data_post'
  patch '/myapi3', :to => 'myapi#data_patch'
  put '/myapi4', :to => 'myapi#create'
  delete '/myapi5', :to => 'myapi#data_delete'
end

class MyapiController #< ApplicationController
  def fetch
    "fetch user"
  end
  def create
    "create data"
  end
  def data_post
    "posting data"
  end
  def data_patch
    "patching data"
  end
  def data_delete
    "deleting data"
  end
end

class MyApiTest < ActionDispatch::IntegrationTest
  def initialize(api)
    @api_name = api
  end

  def get_test
      get('/myapi')
  end

  def post_test(data)
    post('/myapi2', params: {name: data})
  end

  def patch_test(data)
    patch('/myapi3', params: {name: data})
  end

  def put_test(data)
    put('/myapi4', params: {name: data})
  end

  def delete_test(data)
    delete('/myapi5', params: {name: data})
  end
end

module NewRelic::Security
  module Test
    module Instrumentation
      class TestRails < Minitest::Test
        include Rack::Test::Methods
        
        def app
          MyApp
        end

        def test_call
          @api_instance = MyApiTest.new('get')
          @api_instance.get_test
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          #puts http_context.inspect
          method = http_context.method
          time_stamp = http_context.time_stamp
          body = http_context.body
          headers = http_context.headers
          url = http_context.req["PATH_INFO"]
          query_string = http_context.req["QUERY_STRING"]
          clientIP = http_context.req["REMOTE_ADDR"]
          server_port = http_context.req["SERVER_PORT"]
          server_name = http_context.req["SERVER_NAME"]
          protocol = http_context.req["rack.url_scheme"]
          # data verify
          # all routes test
          all_routes =  NewRelic::Security::Agent.agent.route_map
          assert(all_routes.include?("GET@/myapi"))
          assert(all_routes.include?("POST@/myapi2"))
          assert(all_routes.include?("PATCH@/myapi3"))
          assert(all_routes.include?("PUT@/myapi4"))
          assert(all_routes.include?("DELETE@/myapi5"))
          # puts http_context.route
          assert_equal  "GET@/myapi", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "GET", method
          assert_equal "/myapi", url
          assert_equal "", query_string
          assert_equal nil, body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "www.example.com", server_name
          assert_equal "http", protocol
          assert_equal "www.example.com", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_post
          @api_instance = MyApiTest.new('post')
          @api_instance.post_test('abc')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          #puts http_context.inspect
          method = http_context.method
          time_stamp = http_context.time_stamp
          body = http_context.body
          headers = http_context.headers
          url = http_context.req["PATH_INFO"]
          query_string = http_context.req["QUERY_STRING"]
          clientIP = http_context.req["REMOTE_ADDR"]
          server_port = http_context.req["SERVER_PORT"]
          server_name = http_context.req["SERVER_NAME"]
          protocol = http_context.req["rack.url_scheme"]
          # data verify
          #puts http_context.route
          assert_equal  "POST@/myapi2", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "POST", method
          assert_equal "/myapi2", url
          assert_equal "", query_string
          assert_equal "name=abc", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "www.example.com", server_name
          assert_equal "http", protocol
          assert_equal "www.example.com", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_patch
          @api_instance = MyApiTest.new('patch')
          @api_instance.patch_test('abc')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          #puts http_context.inspect
          method = http_context.method
          time_stamp = http_context.time_stamp
          body = http_context.body
          headers = http_context.headers
          url = http_context.req["PATH_INFO"]
          query_string = http_context.req["QUERY_STRING"]
          clientIP = http_context.req["REMOTE_ADDR"]
          server_port = http_context.req["SERVER_PORT"]
          server_name = http_context.req["SERVER_NAME"]
          protocol = http_context.req["rack.url_scheme"]
          # data verify
          #puts http_context.route
          assert_equal  "PATCH@/myapi3", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "PATCH", method
          assert_equal "/myapi3", url
          assert_equal "", query_string
          assert_equal "name=abc", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "www.example.com", server_name
          assert_equal "http", protocol
          assert_equal "www.example.com", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_put
          @api_instance = MyApiTest.new('put')
          @api_instance.put_test('abc')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          #puts http_context.inspect
          method = http_context.method
          time_stamp = http_context.time_stamp
          body = http_context.body
          headers = http_context.headers
          url = http_context.req["PATH_INFO"]
          query_string = http_context.req["QUERY_STRING"]
          clientIP = http_context.req["REMOTE_ADDR"]
          server_port = http_context.req["SERVER_PORT"]
          server_name = http_context.req["SERVER_NAME"]
          protocol = http_context.req["rack.url_scheme"]
          # data verify
          #puts http_context.route
          assert_equal  "PUT@/myapi4", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "PUT", method
          assert_equal "/myapi4", url
          assert_equal "", query_string
          assert_equal "name=abc", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "www.example.com", server_name
          assert_equal "http", protocol
          assert_equal "www.example.com", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_delete
          @api_instance = MyApiTest.new('delete')
          @api_instance.delete_test('abc')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          #puts http_context.inspect
          method = http_context.method
          time_stamp = http_context.time_stamp
          body = http_context.body
          headers = http_context.headers
          url = http_context.req["PATH_INFO"]
          query_string = http_context.req["QUERY_STRING"]
          clientIP = http_context.req["REMOTE_ADDR"]
          server_port = http_context.req["SERVER_PORT"]
          server_name = http_context.req["SERVER_NAME"]
          protocol = http_context.req["rack.url_scheme"]
          # data verify
          #puts http_context.route
          assert_equal  "DELETE@/myapi5", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "DELETE", method
          assert_equal "/myapi5", url
          assert_equal "", query_string
          assert_equal "name=abc", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "www.example.com", server_name
          assert_equal "http", protocol
          assert_equal "www.example.com", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

      end
    end
  end
end
  