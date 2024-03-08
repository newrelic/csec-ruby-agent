# frozen_string_literal: true

require 'set'

module NewRelic::Security
  module Agent
    module Control
      
      # HTTP_ = 'HTTP_'
      # UNDERSCORE = '_'
      # HYPHEN = '-'
      # REQUEST_METHOD = 'REQUEST_METHOD'
      # RACK_INPUT = 'rack.input'
      # CGI_VARIABLES = ::Set.new(%W[ AUTH_TYPE CONTENT_LENGTH CONTENT_TYPE GATEWAY_INTERFACE HTTPS PATH_INFO PATH_TRANSLATED REQUEST_URI QUERY_STRING REMOTE_ADDR REMOTE_HOST REMOTE_IDENT REMOTE_USER REQUEST_METHOD SCRIPT_NAME SERVER_NAME SERVER_PORT SERVER_PROTOCOL SERVER_SOFTWARE rack.url_scheme ])

      class GRPCContext
        
        attr_accessor :time_stamp, :method, :headers, :body, :route, :cache, :url, :server_name, :server_port, :client_ip, :client_port, :is_grpc, :metadata

        def initialize(grpc_request)
          @time_stamp = current_time_millis
          @method = grpc_request[:method]
          @headers = grpc_request[:headers]
          @body = ""
          if defined?(::GRPC::RpcServer)
            ObjectSpace.each_object(::GRPC::RpcServer) do |z|
              # puts "instance_variable GRPC::RpcServer : #{z.inspect}"
              # puts "instance_variable GRPC::RpcServer : #{z.instance_variables}"
              # puts "instance_variable GRPC::RpcServer @server : #{z.instance_variable_get(:@server).inspect}"
              # puts "instance_variable GRPC::RpcServer @rpc_descs : #{z.instance_variable_get(:@rpc_descs).inspect}"
              # puts "instance_variable GRPC::RpcServer @rpc_handlers : #{z.instance_variable_get(:@rpc_handlers).inspect}"
              grpc_host = z.instance_variable_get(:@host_nr)
              grpc_port = z.instance_variable_get(:@port_nr)
              @server_name = "#{grpc_host}:#{grpc_port}"
              @server_port = grpc_port
              @client_ip = grpc_request[:peer].split(COLON)[-2] if grpc_request[:peer]
              @client_port = grpc_request[:peer].split(COLON)[-1] if grpc_request[:peer]
              @url = "grpc://#{grpc_host}:#{grpc_port}/#{@method}"
            end
          end
          @is_grpc = true
          @metadata = { :reflectedMetaData => { :isGrpcClientStream => grpc_request[:is_grpc_client_stream], :isGrpcServerStream => grpc_request[:is_grpc_server_stream] } }
          @cache = {}          
          # NewRelic::Security::Agent.agent.http_request_count.increment
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def self.get_context
          Thread.current[:security_context_data]
        end

        def self.set_context(grpc_request)
          Thread.current[:security_context_data] = GRPCContext.new(grpc_request)
        end

        def self.reset_context
          Thread.current[:security_context_data] = nil if Thread.current[:security_context_data]
        end
      end

    end
  end
end