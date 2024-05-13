module NewRelic::Security
  module Instrumentation
    module HTTPX
      module Session
        module Chain
          def self.instrument!
            ::HTTPX::Session.class_eval do
              include NewRelic::Security::Instrumentation::HTTPX::Session

              alias_method :send_requests_without_security, :send_requests
    
              def send_requests(*args)
                retval = nil
                event = send_requests_on_enter(*args) { retval = send_requests_without_security(*args) }
                send_requests_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end