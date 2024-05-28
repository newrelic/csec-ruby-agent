module NewRelic::Security
  module Instrumentation
    module GRPC
      module RpcDesc
        module Prepend
          include NewRelic::Security::Instrumentation::GRPC::RpcDesc

          def handle_request_response(active_call, mth, inter_ctx)
            grpc_server_on_enter(active_call, mth, inter_ctx, false, false) { super }
          end

          def handle_client_streamer(active_call, mth, inter_ctx)
            grpc_server_on_enter(active_call, mth, inter_ctx, true, false) { super }
          end

          def handle_server_streamer(active_call, mth, inter_ctx)
            grpc_server_on_enter(active_call, mth, inter_ctx, false, true) { super }
          end

          def handle_bidi_streamer(active_call, mth, inter_ctx)
            grpc_server_on_enter(active_call, mth, inter_ctx, true, true) { super }
          end

        end
      end
      
      module ActiveCall
        module Prepend
          include NewRelic::Security::Instrumentation::GRPC::ActiveCall

          def remote_read
            retval = super
            remote_read_on_exit(retval) { return retval }
          end

          def output_metadata
            output_metadata_on_enter { super }
          end

        end
      end

    end
    
  end
end