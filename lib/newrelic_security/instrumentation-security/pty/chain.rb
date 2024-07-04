module NewRelic::Security
  module Instrumentation
    module PTY
      module Chain
        def self.instrument!
          ::PTY.class_eval do
            class << self
              include NewRelic::Security::Instrumentation::PTY

              alias_method :spawn_without_security, :spawn

              def spawn(*var)
                retval = nil
                event = spawn_on_enter(*var) { retval = spawn_without_security(*var) }
                spawn_on_exit(event) { return retval }
              end

              alias_method :getpty_without_security, :getpty

              def getpty(*var, &block)
                retval = nil
                event = getpty_on_enter(*var) { retval = getpty_without_security(*var, &block) }
                getpty_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end
