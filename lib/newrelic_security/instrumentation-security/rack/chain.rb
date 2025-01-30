module NewRelic::Security
  module Instrumentation
    module Rack
      module Builder
        module Chain
          def self.instrument!
            ::Rack::Builder.class_eval do 
              include NewRelic::Security::Instrumentation::Rack::Builder

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
    
  end
end