module NewRelic::Security
  module Instrumentation
    module Excon
      module Connection
        module Chain
          def self.instrument!
            ::Excon::Connection.class_eval do
              include NewRelic::Security::Instrumentation::Excon::Connection

              alias_method :request_without_security, :request
    
              def request(params={}, &block)
                retval = nil
                event = request_on_enter(params) { retval = request_without_security(params, &block) }
                request_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end