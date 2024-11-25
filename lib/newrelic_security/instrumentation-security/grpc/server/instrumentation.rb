require_relative 'prepend'
require_relative 'chain'
require 'json'

module NewRelic::Security
  module Instrumentation
    module GRPC
      module RpcDesc
        def grpc_server_on_enter(active_call, mth, _inter_ctx, is_grpc_client_stream, is_grpc_server_stream)
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          grpc_request = {}
          grpc_request[:headers] = active_call.metadata
          grpc_request[:peer] = active_call.peer
          # puts "mth : #{mth.class} #{mth.methods}"
          # puts "mth :#{mth.original_name}, #{mth.to_s}, #{mth.name}, #{mth.receiver}, #{mth.parameters}, #{mth.owner}, #{mth.unbind}, #{mth.super_method},, #{mth.instance_variables}"
          NewRelic::Security::Agent::Utils.get_app_routes(:grpc, mth) if NewRelic::Security::Agent.agent.route_map.empty?
          grpc_request[:method] = "#{mth.owner}/#{mth.original_name}"
          grpc_request[:is_grpc_client_stream] = is_grpc_client_stream
          grpc_request[:is_grpc_server_stream] = is_grpc_server_stream
          grpc_request[:body] = is_grpc_client_stream ? [] : ::String.new
          NewRelic::Security::Agent::Control::GRPCContext.set_context(grpc_request)
          NewRelic::Security::Agent::Utils.parse_fuzz_header(NewRelic::Security::Agent::Control::GRPCContext.get_context)
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
          return event
        end
      end

      module ActiveCall
        
        def remote_read_on_exit(retval)
          NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
          ctxt = NewRelic::Security::Agent::Control::GRPCContext.get_context
          if ctxt
            if ctxt.metadata[:reflectedMetaData][:isGrpcClientStream]
              ctxt.body << retval.to_json
            else
              ctxt.body += retval.to_json
            end
            ctxt.metadata[:reflectedMetaData][:inputClass] = retval.class.name
          end
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
        end

        def output_metadata_on_enter
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          NewRelic::Security::Agent::Utils.delete_created_files(NewRelic::Security::Agent::Control::GRPCContext.get_context)
          NewRelic::Security::Agent::Control::GRPCContext.reset_context
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
        end
      end
    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:gRPC_Server, ::GRPC::RpcDesc, ::NewRelic::Security::Instrumentation::GRPC::RpcDesc)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:gRPC_Server, ::GRPC::ActiveCall, ::NewRelic::Security::Instrumentation::GRPC::ActiveCall)
