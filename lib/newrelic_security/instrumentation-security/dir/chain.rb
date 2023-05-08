module NewRelic::Security
  module Instrumentation
    module Dir
      module Chain

        def self.instrument!
          ::Dir.class_eval do
            class << self
              include ::NewRelic::Security::Instrumentation::Dir

              alias_method :mkdir_without_security, :mkdir

              def mkdir(*var)
                retval = nil
                event = mkdir_on_enter(*var) { retval = mkdir_without_security(*var) }
                mkdir_on_exit(event, retval) { return retval }
              end

              alias_method :rmdir_without_security, :rmdir

              def rmdir(name)
                retval = nil
                event = rmdir_on_enter(name) { retval = rmdir_without_security(name) }
                rmdir_on_exit(event, retval) { return retval }
              end
              
              alias_method :unlink_without_security, :unlink

              def unlink(name)
                retval = nil
                event = unlink_on_enter(name) { retval = unlink_without_security(name) }
                unlink_on_exit(event, retval) { return retval }
              end

            end
          end
        end

      end
    end
  end
end