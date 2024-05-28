module NewRelic::Security
  module Instrumentation
    module Padrino
      module PathRouter
        module Router
          module Chain
            def self.instrument!
              ::Padrino::PathRouter::Router.class_eval do 
                include NewRelic::Security::Instrumentation::Padrino::PathRouter::Router
  
                alias_method :call_without_security, :call
  
                def call(env, &block)
                  retval = nil
                  event = call_on_enter(env) { retval = call_without_security(env, &block) }
                  call_on_exit(event, retval) { return retval }
                end
  
              end
            end
          end
        end
      end
    end
  end
end