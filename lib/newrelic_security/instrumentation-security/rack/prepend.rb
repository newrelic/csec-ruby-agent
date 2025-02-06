module NewRelic::Security
  module Instrumentation
    module Rack
      module Builder
        module Prepend
          include NewRelic::Security::Instrumentation::Rack::Builder

          def call(env, &block)
            retval = nil
            event = call_on_enter(env) { retval = super }
            call_on_exit(event, retval) { return retval }
          end

        end
      end
    end
  end
end