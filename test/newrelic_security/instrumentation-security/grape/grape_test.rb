require 'grape'
require 'rack/test'

require_relative '../../../test_helper'
require 'newrelic_security/instrumentation-security/grape/instrumentation'

class GrapeTestApp < Grape::API
  namespace :user do
    resource :login do
      get do
        'please log in'
      end

      route_param :id do
        get do
          "Welcome #{params[:id]}"
        end
      end
    end

    resource :profile do
      get do
        "Hello #{params[:q]}"
      end
    end

    resource :new do
      post do
        data = request.body.read
        "User created: #{data}"
      end
    end
  end
end

module NewRelic::Security
  module Test
    module Instrumentation
      class TestGrape < Minitest::Test
        include Rack::Test::Methods

        def app
          GrapeTestApp
        end

        def test_get
          response = get('/user/login')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context

          assert_equal  "GET@/user/login", http_context.route
          assert_equal Integer, http_context.time_stamp.class
          assert_equal "GET", http_context.method
          assert_equal "/user/login", http_context.req["PATH_INFO"]
          assert_equal "", http_context.req["QUERY_STRING"]
          assert_nil http_context.body
          assert_equal "127.0.0.1", http_context.req["REMOTE_ADDR"]
          assert_equal "80", http_context.req["SERVER_PORT"]
          assert_equal "example.org", http_context.req["SERVER_NAME"]
          assert_equal "http", http_context.req["rack.url_scheme"]
          assert_equal "example.org", http_context.headers["host"]
          assert_equal "HTTP/1.0", http_context.headers["version"] if Rack::Test::VERSION > '0.6.3'
        end

        def test_get_with_path_param
          get('/user/login/1')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context

          assert_equal 200, last_response.status
          assert_equal 'Welcome 1', last_response.body
          assert_equal  "GET@/user/login/:id", http_context.route
          assert_equal Integer, http_context.time_stamp.class
          assert_equal "GET", http_context.method
          assert_equal "/user/login/1", http_context.req["PATH_INFO"]
          assert_equal "", http_context.req["QUERY_STRING"]
          assert_nil http_context.body
          assert_equal "127.0.0.1", http_context.req["REMOTE_ADDR"]
          assert_equal "80", http_context.req["SERVER_PORT"]
          assert_equal "example.org", http_context.req["SERVER_NAME"]
          assert_equal "http", http_context.req["rack.url_scheme"]
          assert_equal "example.org", http_context.headers["host"]
          assert_equal "HTTP/1.0", http_context.headers["version"] if Rack::Test::VERSION > '0.6.3'
        end

        def test_get_with_query_param
          get('/user/profile?q=Prateek')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context

          assert_equal 200, last_response.status
          assert_equal 'Hello Prateek', last_response.body
          assert_equal  "GET@/user/profile", http_context.route
          assert_equal Integer, http_context.time_stamp.class
          assert_equal "GET", http_context.method
          assert_equal "/user/profile", http_context.req["PATH_INFO"]
          assert_equal "q=Prateek", http_context.req["QUERY_STRING"]
          assert_nil http_context.body
          assert_equal "127.0.0.1", http_context.req["REMOTE_ADDR"]
          assert_equal "80", http_context.req["SERVER_PORT"]
          assert_equal "example.org", http_context.req["SERVER_NAME"]
          assert_equal "http", http_context.req["rack.url_scheme"]
          assert_equal "example.org", http_context.headers["host"]
          assert_equal "HTTP/1.0", http_context.headers["version"] if Rack::Test::VERSION > '0.6.3'
        end

        def test_get_url_not_found
          get('/user/404')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context

          assert_equal 404, last_response.status
          assert last_response.not_found?
          assert_nil http_context.route
          assert_equal Integer, http_context.time_stamp.class
          assert_equal "GET", http_context.method
          assert_equal "/user/404", http_context.req["PATH_INFO"]
          assert_equal "", http_context.req["QUERY_STRING"]
          assert_nil http_context.body
          assert_equal "127.0.0.1", http_context.req["REMOTE_ADDR"]
          assert_equal "80", http_context.req["SERVER_PORT"]
          assert_equal "example.org", http_context.req["SERVER_NAME"]
          assert_equal "http", http_context.req["rack.url_scheme"]
          assert_equal "example.org", http_context.headers["host"]
          assert_equal "HTTP/1.0", http_context.headers["version"] if Rack::Test::VERSION > '0.6.3'
        end

        def test_post_some_data
          post('/user/new', 'Prateek')
          http_context = NewRelic::Security::Agent::Control::HTTPContext.get_context

          assert_equal 201, last_response.status
          assert_equal 'User created: Prateek', last_response.body
          assert_equal  "POST@/user/new", http_context.route
          assert_equal Integer, http_context.time_stamp.class
          assert_equal "POST", http_context.method
          assert_equal "/user/new", http_context.req["PATH_INFO"]
          assert_equal "", http_context.req["QUERY_STRING"]
          assert_equal "Prateek", http_context.body
          assert_equal "127.0.0.1", http_context.req["REMOTE_ADDR"]
          assert_equal "80", http_context.req["SERVER_PORT"]
          assert_equal "example.org", http_context.req["SERVER_NAME"]
          assert_equal "http", http_context.req["rack.url_scheme"]
          assert_equal "example.org", http_context.headers["host"]
          assert_equal "HTTP/1.0", http_context.headers["version"] if Rack::Test::VERSION > '0.6.3'
        end

      end
    end
  end
end
