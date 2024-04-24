module NewRelic::Security
  module Instrumentation
    module HTTPX
      module Session
        module Prepend
          include NewRelic::Security::Instrumentation::HTTPX::Session

          def send_requests(*args)
            retval = nil
            event = send_requests_on_enter(*args) { retval = super }
            send_requests_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end