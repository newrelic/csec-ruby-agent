module NewRelic::Security
  module Instrumentation
    module Kernel
      module Chain
        def self.instrument!
          ::Object.class_eval do
            include NewRelic::Security::Instrumentation::Kernel

            private

            # TODO: This hook is useful for applying instrumentation on dynamically loaded modules, dynamic loading of module is unsupported for now.
            # alias_method :require_without_security, :require

            # def require(name)
            #   retval = nil
            #   event = require_on_enter(name) { retval = require_without_security(name) }
            #   require_on_exit(event, retval, name) { return retval }
            # end
            
            alias_method :system_without_security, :system

            def system(*var)
              retval = nil
              event = system_on_enter(*var) { retval = system_without_security(*var) }
              system_on_exit(event, retval) { return retval }
            end

            alias_method :backtick_without_security, :`

            def `(cmd)
              retval = nil
              event = backtick_on_enter(cmd) { retval = backtick_without_security(cmd) }
              backtick_on_exit(event) { return retval }
            end

            alias_method :spawn_without_security, :spawn

            def spawn(*var)
              retval = nil
              event = spawn_on_enter(*var) { retval = spawn_without_security(*var) }
              spawn_on_exit(event, retval) { return retval }
            end

            alias_method :exec_without_security, :exec

            def exec(*var)
              retval = nil
              event = exec_on_enter(*var) { retval = exec_without_security(*var) }
              exec_on_exit(event) { return retval }
            end

            alias_method :open_without_security, :open

            def open(*args, **kwargs)
              retval = nil
              event = open_on_enter(*args, **kwargs) { retval = open_without_security(*args, **kwargs) }
              open_on_exit(event, retval) { return retval }
            end

            unless NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.insecure_settings']
              alias_method :rand_without_security, :rand

              def rand(*args)
                retval = nil
                event = rand_on_enter { retval = rand_without_security(*args) }
                rand_on_exit(event) { return retval }
              end
            end
            
          end
        end
      end
    end
  end
end