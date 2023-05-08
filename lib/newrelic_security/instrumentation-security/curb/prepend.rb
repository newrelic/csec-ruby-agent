module NewRelic::Security
  module Instrumentation
    module Curl
      module Multi
        module Prepend
          include NewRelic::Security::Instrumentation::Curl::Multi

          def perform(*args, &block)
            retval = nil
            event = perform_on_enter(*args) { retval = super }
            perform_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end