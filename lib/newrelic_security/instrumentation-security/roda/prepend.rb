module NewRelic::Security
  module Instrumentation
    module Roda
      module Prepend
        include NewRelic::Security::Instrumentation::Roda

        def _roda_handle_main_route(*args)
          retval = nil
          event = _roda_handle_main_route_on_enter(self.env) { retval = super }
          _roda_handle_main_route_on_exit(event, retval) { return retval }
        end
        
      end
    end
  end
end