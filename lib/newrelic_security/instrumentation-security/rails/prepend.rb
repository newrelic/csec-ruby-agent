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
      module Routing
        module RouteSet
          module Dispatcher
            module Prepend
              include NewRelic::Security::Instrumentation::ActionDispatch::Routing::RouteSet::Dispatcher

              def serve(req)
                retval = nil
                event = serve_on_enter(req) { retval = super }
                serve_on_exit(event, retval) { return retval }
              end
            end
          end
        end
      end
    end
  end
end