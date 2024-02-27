module NewRelic::Security
  module Instrumentation
    module GRPC
      module ClientStub
        module Prepend
          include NewRelic::Security::Instrumentation::GRPC::ClientStub

          def request_response(method, req, marshal, unmarshal, deadline: nil, return_op: false, parent: nil, credentials: nil, metadata: {}) # rubocop:disable Metrics/ParameterLists
            retval = nil
            event = request_response_on_enter(method, req, marshal, unmarshal, deadline, return_op, parent, credentials, metadata) { retval = super }
            request_response_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end