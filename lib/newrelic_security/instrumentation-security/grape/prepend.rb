module NewRelic::Security
  module Instrumentation
    module Grape
      module API
        module Instance
          module Prepend
            include NewRelic::Security::Instrumentation::Grape::API::Instance
                        
            def call(env)
              retval = nil
              event = call_on_enter(env) { retval = super(env) }
              call_on_exit(event, retval) { return retval }
            end

          end
        end
      end

      module Router
        module Prepend
          include NewRelic::Security::Instrumentation::Grape::Router

          def prepare_env_from_route(env, route)
            prepare_env_from_route_on_enter(route) { super }
          end
        end
      end
    end
  end
end