module NewRelic::Security
  module Instrumentation
    module Redis
      module Client
        module Prepend
          include NewRelic::Security::Instrumentation::Redis::Client
  
          if ::Redis::VERSION <= '5'
            def call(command, &block)
              retval = nil
              event = call_v_on_enter(command) { retval = super }
              call_v_on_exit(event) { return retval }
            end
          else
            def call_v(command, &block)
              retval = nil
              event = call_v_on_enter(command) { retval = super }
              call_v_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end