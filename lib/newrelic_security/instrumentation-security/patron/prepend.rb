module NewRelic::Security
  module Instrumentation
    module Patron
      module Session
        module Prepend
          include NewRelic::Security::Instrumentation::Patron::Session

          def request(action, url, headers, options = {})
            retval = nil
            event = request_on_enter(action, url, headers, options) { retval = super }
            request_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end