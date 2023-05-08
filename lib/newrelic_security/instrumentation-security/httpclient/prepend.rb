module NewRelic::Security
  module Instrumentation
    module HTTPClient
      module Prepend
        include NewRelic::Security::Instrumentation::HTTPClient

        def do_request(method, uri, query, body, header, &block)
          retval = nil
          event = do_request_on_enter(method, uri, query, body, header) { retval = super }
          do_request_on_exit(event) { return retval }
        end

        def do_request_async(method, uri, query, body, header)
          retval = nil
          event = do_request_async_on_enter(method, uri, query, body, header) { retval = super }
          do_request_async_on_exit(event) { return retval }
        end

      end
    end
  end
end