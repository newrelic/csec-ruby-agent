module NewRelic::Security
  module Instrumentation
    module GRPC
      module ClientStub
        module Chain
          def self.instrument!
            ::GRPC::ClientStub.class_eval do
              include NewRelic::Security::Instrumentation::GRPC::ClientStub

              alias_method :request_response_without_security, :request_response
    
              def request_response(method, req, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}) # rubocop:disable Metrics/ParameterLists
                retval = nil
                event = grpc_client_on_enter(method, metadata) { retval = request_response_without_security(method, req, marshal, unmarshal, deadline, return_op, parent, credentials, metadata) }
                grpc_client_on_exit(event) { return retval }
              end

              alias_method :server_streamer_without_security, :server_streamer

              def server_streamer(method, req, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}, &blk) # rubocop:disable Metrics/ParameterLists
                retval = nil
                event = grpc_client_on_enter(method, metadata) { retval = server_streamer_without_security(method, req, marshal, unmarshal, deadline, return_op, parent, credentials, metadata, &blk) }
                grpc_client_on_exit(event) { return retval }
              end

              alias_method :client_streamer_without_security, :client_streamer

              def client_streamer(method, requests, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}) # rubocop:disable Metrics/ParameterLists
                retval = nil
                event = grpc_client_on_enter(method, metadata) { retval = client_streamer_without_security(method, requests, marshal, unmarshal, deadline, return_op, parent, credentials, metadata) }
                grpc_client_on_exit(event) { return retval }
              end

              alias_method :bidi_streamer_without_security, :bidi_streamer

              def bidi_streamer(method, requests, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}, &blk) # rubocop:disable Metrics/ParameterLists
                retval = nil
                event = grpc_client_on_enter(method, metadata) { retval = bidi_streamer_without_security(method, requests, marshal, unmarshal, deadline, return_op, parent, credentials, metadata, &blk) }
                grpc_client_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end