module NewRelic::Security
  module Instrumentation
    module Redis
      module Client
        module Chain

          def self.instrument!
            ::Redis::Client.class_eval do
              include NewRelic::Security::Instrumentation::Redis::Client

              alias_method :call_v_without_security, :call_v

              def call_v(command, &block)
                retval = nil
                event = call_v_on_enter(command) { retval = call_v_without_security(command, &block) }
                call_v_on_exit(event) { return retval }
              end
              
            end
          end
        end
      end
    end
  end
end