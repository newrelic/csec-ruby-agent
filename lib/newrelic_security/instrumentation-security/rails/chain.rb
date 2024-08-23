module NewRelic::Security
  module Instrumentation
    module Rails
      module Engine
        module Chain
          def self.instrument!
            ::Rails::Engine.class_eval do 
              include NewRelic::Security::Instrumentation::Rails::Engine

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

    module ActionDispatch
      module Journey
        module Router
          module Chain
            def self.instrument!
              ::ActionDispatch::Journey::Router.class_eval do
                include NewRelic::Security::Instrumentation::ActionDispatch::Journey::Router

                alias_method :find_routes_without_security, :find_routes

                def find_routes(req)
                  retval = nil
                  event = find_routes_on_enter(req) { retval = find_routes_without_security(req) }
                  find_routes_on_exit(event, retval) { return retval }
                end
              end
            end
          end
        end
      end
    end

    module ActionDispatch
      module Routing
        module RouteSet
          module Dispatcher
            module Chain
              def self.instrument!
                ::ActionDispatch::Routing::RouteSet::Dispatcher.class_eval do
                  include NewRelic::Security::Instrumentation::ActionDispatch::Routing::RouteSet::Dispatcher

                  alias_method :serve_without_security, :serve

                  def serve(req)
                    retval = nil
                    event = serve_on_enter(req) { retval = serve_without_security(req) }
                    serve_on_exit(event, retval) { return retval }
                  end
                end
              end
            end
          end
        end
      end
    end
    
  end
end