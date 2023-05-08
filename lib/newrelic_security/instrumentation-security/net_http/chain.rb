module NewRelic::Security
  module Instrumentation
    module NetHTTP
      module Chain
        def self.instrument!
          ::Net::HTTP.class_eval do
            include NewRelic::Security::Instrumentation::NetHTTP

            alias_method :transport_request_without_security, :transport_request
  
            def transport_request(req, &block)
              retval = nil
              event = transport_request_on_enter(req) { retval = transport_request_without_security(req, &block) }
              transport_request_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end