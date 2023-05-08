module NewRelic::Security
  module Instrumentation
    module Sinatra
      module Base
        module Chain
          def self.instrument!
            ::Sinatra::Base.class_eval do 
              include NewRelic::Security::Instrumentation::Sinatra::Base

              alias_method :call_without_security, :call

              def call(env)
                retval = nil
                event = call_on_enter(env) { retval = call_without_security(env) }
                call_on_exit(event, retval) { return retval }
              end

              alias_method :route_eval_without_security, :route_eval

              def route_eval(&block)
                route_eval_on_enter { route_eval_without_security(&block) }
              end
            end
          end
        end
      end
    end
  end
end