module NewRelic::Security
  module Instrumentation
    module HTTPrb
      module Prepend
        include NewRelic::Security::Instrumentation::HTTPrb
                
        def perform(request, options)
          retval = nil
          event = perform_on_enter(request, options) { retval = super }
          perform_on_exit(event) { return retval }
        end

      end
    end
  end
end