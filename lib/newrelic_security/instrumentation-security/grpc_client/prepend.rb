module NewRelic::Security
  module Instrumentation
    module GRPC
      module ClientStub
        module Prepend
          include NewRelic::Security::Instrumentation::GRPC::ClientStub

          def request_response(method, req, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}) # rubocop:disable Metrics/ParameterLists
            retval = nil
            event = grpc_client_on_enter(method, metadata) { retval = super }
            grpc_client_on_exit(event) { return retval }
          end

          def server_streamer(method, req, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}, &blk) # rubocop:disable Metrics/ParameterLists
            retval = nil
            event = grpc_client_on_enter(method, metadata) { retval = super }
            grpc_client_on_exit(event) { return retval }
          end

          def client_streamer(method, requests, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}) # rubocop:disable Metrics/ParameterLists
            retval = nil
            event = grpc_client_on_enter(method, metadata) { retval = super }
            grpc_client_on_exit(event) { return retval }
          end

          def bidi_streamer(method, requests, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}, &blk) # rubocop:disable Metrics/ParameterLists
            retval = nil
            event = grpc_client_on_enter(method, metadata) { retval = super }
            grpc_client_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end