require 'sinatra'
require 'rack/test'

require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/sinatra/instrumentation'

class SinatraTestApp < Sinatra::Base
  configure do
    set :my_condition do |boolean|
      condition do
        halt 404 unless boolean
      end
    end
  end

  # test apis
  get '/user/login' do
    'please log in'
  end
  post '/user/signup' do
    # puts "post"
    'please sign up'
  end
  put '/user/user1' do
    # puts "put"
    'put user 1'
  end
  patch '/user/user2' do
    # puts "patch"
    'patch user 2'
  end
  delete '/user/user3' do
    # puts "delete"
    'delete user 3'
  end

end

module NewRelic::Security
  module Test
    module Instrumentation
      class TestSinatra < Minitest::Test
        include Rack::Test::Methods
        include ::NewRelic::Security::Instrumentation::Sinatra

        def app
          SinatraTestApp
        end
        
        # Test call hook
        def test_call_get
          # GET method test
          get('/user/login', "John")
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          # puts http_context.inspect
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
          assert_equal  "GET@/user/login", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "GET", method
          assert_equal "/user/login", url
          assert_equal "John", query_string
          assert_equal "", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "example.org", server_name
          assert_equal "http", protocol
          assert_equal "example.org", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_post
          # POST method test
          post('/user/signup', "Jack")
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          # puts http_context.inspect

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
          assert_equal  "POST@/user/signup", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "POST", method
          assert_equal "/user/signup", url
          assert_equal "", query_string
          assert_equal "Jack", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "example.org", server_name
          assert_equal "http", protocol
          assert_equal "example.org", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end
        
        def test_call_put
          # PUT method test
          put('/user/user1', "Nor")
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          # puts http_context.inspect

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
          assert_equal  "PUT@/user/user1", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "PUT", method
          assert_equal "/user/user1", url
          assert_equal "", query_string
          assert_equal "Nor", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "example.org", server_name
          assert_equal "http", protocol
          assert_equal "example.org", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_patch
          # PATCH method test
          patch('/user/user2', "Tiec")
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          # puts http_context.inspect

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
          assert_equal  "PATCH@/user/user2", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "PATCH", method
          assert_equal "/user/user2", url
          assert_equal "", query_string
          assert_equal "Tiec", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "example.org", server_name
          assert_equal "http", protocol
          assert_equal "example.org", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

        def test_call_delete
          # DELETE method test
          delete('/user/user3',"Temp")
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.clear_context
          # puts http_context.inspect

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
          assert_equal  "DELETE@/user/user3", http_context.route
          assert_equal Integer, time_stamp.class
          assert_equal "DELETE", method
          assert_equal "/user/user3", url
          assert_equal "", query_string
          assert_equal "Temp", body
          assert_equal "127.0.0.1", clientIP
          assert_equal "80", server_port
          assert_equal "example.org", server_name
          assert_equal "http", protocol
          assert_equal "example.org", headers["host"]
          assert_equal "HTTP/1.0", headers["version"]
        end

      end
    end
  end
end
  