# frozen_string_literal: true

require 'set'

module NewRelic::Security
  module Agent
    module Control
      
      class GRPCContext
        
        attr_accessor :time_stamp, :method, :headers, :body, :route, :cache, :fuzz_files, :url, :server_name, :server_port, :client_ip, :client_port, :is_grpc, :metadata, :event_counter

        def initialize(grpc_request)
          @time_stamp = current_time_millis
          @method = grpc_request[:method]
          @headers = grpc_request[:headers]
          @body = ::String.new
          if defined?(::GRPC::RpcServer)
            ObjectSpace.each_object(::GRPC::RpcServer) do |z|
              grpc_host = z.instance_variable_get(:@host_nr)
              grpc_port = z.instance_variable_get(:@port_nr)
              @server_name = "#{grpc_host}:#{grpc_port}"
              @server_port = grpc_port
              @client_ip = grpc_request[:peer].rpartition(COLON)[0] if grpc_request[:peer]
              @client_port = grpc_request[:peer].rpartition(COLON)[-1] if grpc_request[:peer]
              @url = "grpc://#{grpc_host}:#{grpc_port}/#{@method}"
            end
          end
          @is_grpc = true
          @metadata = { :reflectedMetaData => { :isGrpcClientStream => grpc_request[:is_grpc_client_stream], :isGrpcServerStream => grpc_request[:is_grpc_server_stream] } }
          @cache = {}
          @fuzz_files = ::Set.new
          @event_counter = 0
          NewRelic::Security::Agent.agent.http_request_count.increment
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