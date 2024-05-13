module NewRelic::Security
  module Instrumentation
    module Typhoeus
      module Request
        module Prepend
          include NewRelic::Security::Instrumentation::Typhoeus::Request

          def run
            retval = nil
            event = run_on_enter { retval = super }
            run_on_exit(event) { return retval }
          end

        end
      end

      module Hydra
        module Prepend
          include NewRelic::Security::Instrumentation::Typhoeus::Hydra

          def run
            retval = nil
            event = run_on_enter { retval = super }
            run_on_exit(event) { return retval }
          end

        end
      end

    end
  end
end