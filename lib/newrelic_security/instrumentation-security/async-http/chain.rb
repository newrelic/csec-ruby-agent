module NewRelic::Security
  module Instrumentation
    module AsyncHttp
      module Chain
        def self.instrument!
          ::Async::HTTP::Internet.class_eval do
            include NewRelic::Security::Instrumentation::AsyncHttp

            alias_method :call_without_security, :call
  
            def call(method, url, headers = nil, body = nil)
              retval = nil
              event = call_on_enter(method, url, headers = nil, body = nil) { retval = call_without_security(method, url, headers, body) }
              call_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end