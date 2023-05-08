module NewRelic::Security
  module Instrumentation
    module Curl
      module Multi
        module Chain

          def self.instrument!
            ::Curl::Multi.class_eval do
              include NewRelic::Security::Instrumentation::Curl::Multi

              alias_method :perform_without_security, :perform
    
              def perform(*args, &block)
                retval = nil
                event = perform_on_enter(*args) { retval = perform_without_security(*args, &block) }
                perform_on_exit(event) { return retval }
              end
              
            end
          end

        end
      end
    end
  end
end