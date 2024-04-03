module NewRelic::Security
  module Instrumentation
    module Kernel
      module Prepend
        include NewRelic::Security::Instrumentation::Kernel

        private

        # TODO: This hook is useful for applying instrumentation on dynamically loaded modules, dynamic loading of module is unsupported for now.
        # def require(name)
        #   retval = nil
        #   event = require_on_enter(name) { retval = super }
        #   require_on_exit(event, retval, name) { return retval }
        # end

        def system(*var)
          retval = nil
          event = system_on_enter(*var) { retval = super }
          system_on_exit(event, retval) { return retval }
        end

        def `(cmd)
          retval = nil
          event = backtick_on_enter(cmd) { retval = super }
          backtick_on_exit(event) { return retval }
        end

        def spawn(*var)
          retval = nil
          event = spawn_on_enter(*var) { retval = super }
          spawn_on_exit(event, retval) { return retval }
        end
        
        # TODO: Add fork hook if required
        def exec(*var)
          retval = nil
          event = exec_on_enter(*var) { retval = super }
          exec_on_exit(event) { return retval }
        end

        def open(*args, **kwargs)
          retval = nil
          event = open_on_enter(*args, **kwargs) { retval = super }
          open_on_exit(event, retval) { return retval }
        end

      end
    end
  end
end