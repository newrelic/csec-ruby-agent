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
                event = request_response_on_enter(method, req, marshal, unmarshal, deadline, return_op, parent, credentials, metadata) { retval = request_response_without_security(method, req, marshal, unmarshal, deadline, return_op, parent, credentials, metadata) }
                request_response_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end