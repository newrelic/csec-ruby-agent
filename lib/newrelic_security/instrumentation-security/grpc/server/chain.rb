module NewRelic::Security
  module Instrumentation
    module GRPC
      module RpcDesc
        module Chain
          def self.instrument!
            ::GRPC::RpcDesc.class_eval do
              include NewRelic::Security::Instrumentation::GRPC::RpcDesc

              alias_method :handle_request_response_without_security, :handle_request_response
    
              def handle_request_response(active_call, mth, inter_ctx)
                grpc_server_on_enter(active_call, mth, inter_ctx, false, false) { return handle_request_response_without_security(active_call, mth, inter_ctx) }
              end

              alias_method :handle_client_streamer_without_security, :handle_client_streamer
    
              def handle_client_streamer(active_call, mth, inter_ctx)
                grpc_server_on_enter(active_call, mth, inter_ctx, true, false) { return handle_request_response_without_security(active_call, mth, inter_ctx) }
              end

              alias_method :handle_server_streamer_without_security, :handle_server_streamer
    
              def handle_server_streamer(active_call, mth, inter_ctx)
                grpc_server_on_enter(active_call, mth, inter_ctx, false, true) { return handle_request_response_without_security(active_call, mth, inter_ctx) }
              end

              alias_method :handle_bidi_streamer_without_security, :handle_bidi_streamer
    
              def handle_bidi_streamer(active_call, mth, inter_ctx)
                grpc_server_on_enter(active_call, mth, inter_ctx, true, true) { return handle_request_response_without_security(active_call, mth, inter_ctx) }
              end
            end
          end
        end
      end

      module ActiveCall
        module Chain
          def self.instrument!
            ::GRPC::ActiveCall.class_eval do
              include NewRelic::Security::Instrumentation::GRPC::ActiveCall

              alias_method :remote_read_without_security, :remote_read

              def remote_read
                retval = remote_read_without_security
                remote_read_on_exit(retval) { return retval }
              end

              alias_method :output_metadata_without_security, :output_metadata
    
              def output_metadata
                output_metadata_on_enter { return output_metadata_without_security }
              end
            end
          end
        end
      end
    end
  end
end