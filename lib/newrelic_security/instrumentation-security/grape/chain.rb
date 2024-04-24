module NewRelic::Security
  module Instrumentation
    module Grape
      module API
        module Instance
          module Chain
            def self.instrument!
              ::Grape::API::Instance.class_eval do 
                include NewRelic::Security::Instrumentation::Grape::API::Instance
                
                alias_method :call_without_security, :call
                
                def call(env)
                  retval = nil
                  event = call_on_enter(env) { retval = call_without_security(env) }
                  call_on_exit(event, retval) { return retval }
                end

              end
            end
          end
        end
      end

      module Router
        module Chain
          def self.instrument!
            ::Grape::Router.class_eval do
              include NewRelic::Security::Instrumentation::Grape::Router

              alias_method :prepare_env_from_route_without_security, :prepare_env_from_route

              def prepare_env_from_route(env, route)
                prepare_env_from_route_on_enter(route) { prepare_env_from_route_without_security(env, route) }
              end
            end
          end
        end
      end
    end
  end
end