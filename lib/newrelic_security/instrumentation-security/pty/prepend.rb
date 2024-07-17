module NewRelic::Security
  module Instrumentation
    module PTY
      module Prepend
        include NewRelic::Security::Instrumentation::PTY

        def spawn(*var)
          retval = nil
          event = spawn_on_enter(*var) { retval = super }
          spawn_on_exit(event) { return retval }
        end

        def getpty(*var, &block)
          retval = nil
          event = getpty_on_enter(*var) { retval = super }
          getpty_on_exit(event) { return retval }
        end

      end
    end
  end
end
