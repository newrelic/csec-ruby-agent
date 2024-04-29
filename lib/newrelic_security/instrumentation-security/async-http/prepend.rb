module NewRelic::Security
  module Instrumentation
    module AsyncHttp
      module Prepend
        include NewRelic::Security::Instrumentation::AsyncHttp

        def call(method, url, headers = nil, body = nil)
          retval = nil
          event = call_on_enter(method, url, headers, body) { retval = super }
          call_on_exit(event) { return retval }
        end

      end
    end
  end
end