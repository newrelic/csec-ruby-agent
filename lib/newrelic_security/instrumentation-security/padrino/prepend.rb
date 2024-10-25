module NewRelic::Security
  module Instrumentation
    module Padrino
      module PathRouter
        module Router
          module Prepend
            include NewRelic::Security::Instrumentation::Padrino::PathRouter::Router
  
            def call(env, &block)
              retval = nil
              event = call_on_enter(env) { retval = super }
              call_on_exit(event, retval) { return retval }
            end
  
          end
        end
      end

      module Router
        module Prepend
          include NewRelic::Security::Instrumentation::Padrino::Router

          def call(env, &block)
            retval = super
            call_on_exit(retval) { return retval }
          end

        end
      end
    end
  end
end