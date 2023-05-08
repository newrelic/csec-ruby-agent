module NewRelic::Security
  module Instrumentation
    module NetHTTP
      module Prepend
        include NewRelic::Security::Instrumentation::NetHTTP

        def transport_request(req, &block)
          retval = nil
          event = transport_request_on_enter(req) { retval = super }
          transport_request_on_exit(event) { return retval }
        end

      end
    end
  end
end