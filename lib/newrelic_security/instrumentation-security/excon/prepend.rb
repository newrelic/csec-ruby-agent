module NewRelic::Security
  module Instrumentation
    module Excon
      module Connection
        module Prepend
          include NewRelic::Security::Instrumentation::Excon::Connection
  
          def request(params={}, &block)
            retval = nil
            event = request_on_enter(params) { retval = super }
            request_on_exit(event) { return retval }
          end
        end
      end
    end
  end
end