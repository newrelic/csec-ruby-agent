module NewRelic::Security
  module Instrumentation
    module Patron
      module Session
        module Chain
          def self.instrument!
            ::Patron::Session.class_eval do
              include NewRelic::Security::Instrumentation::Patron::Session

              alias_method :request_without_security, :request
    
              def request(action, url, headers, options = {})
                retval = nil
                event = request_on_enter(action, url, headers, options) { retval = request_without_security(action, url, headers, options) }
                request_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end