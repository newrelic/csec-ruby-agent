module NewRelic::Security
  module Instrumentation
    module File
      module Chain

        def self.instrument!
          ::File.class_eval do
            class << self
              include ::NewRelic::Security::Instrumentation::File

              alias_method :delete_without_security, :delete

              def delete(*var)
                retval = nil
                event = delete_on_enter(*var) { retval = delete_without_security(*var) }
                delete_on_exit(event, retval) { return retval }
              end
              
              alias_method :unlink_without_security, :unlink

              def unlink(*var)
                retval = nil
                event = unlink_on_enter(*var) { retval = unlink_without_security(*var) }
                unlink_on_exit(event, retval) { return retval }
              end

            end
          end
        end
        
      end
    end
  end
end