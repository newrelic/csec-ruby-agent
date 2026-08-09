module NewRelic::Security
  module Instrumentation
    module Dalli
      module Client
        module Prepend
          include NewRelic::Security::Instrumentation::Dalli::Client
  
          def perform(*all_args)
            retval = nil
            event = perform_on_enter(*all_args) { retval = super }
            perform_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end