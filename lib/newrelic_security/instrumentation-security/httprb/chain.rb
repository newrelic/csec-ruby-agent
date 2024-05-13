module NewRelic::Security
  module Instrumentation
    module HTTPrb
      module Chain
        def self.instrument!
          ::HTTP::Client.class_eval do
            include NewRelic::Security::Instrumentation::HTTPrb
                        
            alias_method :perform_without_security, :perform
  
            def perform(request, options)
              retval = nil
              event = perform_on_enter(request, options) { retval = perform_without_security(request, options) }
              perform_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end