module NewRelic::Security
  module Instrumentation
    module Typhoeus
      module Request
        module Chain
          def self.instrument!
            ::Typhoeus::Request.class_eval do
              include NewRelic::Security::Instrumentation::Typhoeus::Request

              alias_method :run_without_security, :run
    
              def run
                retval = nil
                event = run_on_enter { retval = run_without_security }
                run_on_exit(event) { return retval }
              end
            end
          end
        end
      end

      module Hydra
        module Chain
          def self.instrument!
            ::Typhoeus::Hydra.class_eval do
              include NewRelic::Security::Instrumentation::Typhoeus::Hydra

              alias_method :run_without_security, :run
    
              def run
                retval = nil
                event = run_on_enter { retval = run_without_security }
                run_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end