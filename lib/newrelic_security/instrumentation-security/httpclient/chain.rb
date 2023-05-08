module NewRelic::Security
  module Instrumentation
    module HTTPClient
      module Chain
        def self.instrument!
          ::HTTPClient.class_eval do
            include NewRelic::Security::Instrumentation::HTTPClient

            alias_method :do_request_without_security, :do_request
  
            def do_request(method, uri, query, body, header, &block)
              retval = nil
              event = do_request_on_enter(method, uri, query, body, header) { retval = do_request_without_security(method, uri, query, body, header, &block) }
              do_request_on_exit(event) { return retval }
            end

            alias_method :do_request_async_without_security, :do_request_async
  
            def do_request_async(method, uri, query, body, header, &block)
              retval = nil
              event = do_request_async_on_enter(method, uri, query, body, header) { retval = do_request_async_without_security(method, uri, query, body, header, &block) }
              do_request_async_on_exit(event) { return retval }
            end

          end
        end
      end
    end
  end
end