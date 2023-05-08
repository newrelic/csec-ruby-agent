module NewRelic::Security
  module Instrumentation
    module Sinatra
      module Base
        module Prepend
          include NewRelic::Security::Instrumentation::Sinatra::Base

          def call(env)
            retval = nil
            event = call_on_enter(env) { retval = super }
            call_on_exit(event, retval) { return retval }
          end

          def route_eval
            route_eval_on_enter { super }
          end
        end
      end
    end
  end
end