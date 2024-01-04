module NewRelic::Security
  module Instrumentation
    module Sinatra
      module Chain
        def self.instrument!
          ::Roda.class_eval do 
            include NewRelic::Security::Instrumentation::Roda

            alias_method :_roda_handle_main_route_without_security, :_roda_handle_main_route

            def _roda_handle_main_route(*args)
              retval = nil
              event = _roda_handle_main_route_on_enter(self.env) { retval = _roda_handle_main_route_without_security(*args) }
              _roda_handle_main_route_on_exit(event, retval) { return retval }
            end

          end
        end
      end
    end
  end
end