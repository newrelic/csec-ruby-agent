module NewRelic::Security
  module Instrumentation
    module Dalli
      module Client
        module Chain

          def self.instrument!
            ::Dalli::Client.class_eval do
              include NewRelic::Security::Instrumentation::Dalli::Client

              alias_method :perform_without_security, :perform

              def perform(*all_args)
                retval = nil
                event = perform_on_enter(*all_args) { retval = perform_without_security(*all_args) }
                perform_on_exit(event) { return retval }
              end
              
            end
          end
        end
      end
    end
  end
end