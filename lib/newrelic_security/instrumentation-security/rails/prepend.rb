module NewRelic::Security
  module Instrumentation
    module Rails
      module Engine
        module Prepend
          include NewRelic::Security::Instrumentation::Rails::Engine

          def call(env)
            retval = nil
            event = call_on_enter(env) { retval = super }
            call_on_exit(event, retval) { return retval }
          end
        end
      end
    end

    module ActionDispatch
      module Journey
        module Router
          module Prepend
            include NewRelic::Security::Instrumentation::ActionDispatch::Journey::Router

            def find_routes(req)
              retval = nil
              event = find_routes_on_enter(req) { retval = super }
              find_routes_on_exit(event, retval) { return retval }
            end
          end
        end
      end
    end
  end
end