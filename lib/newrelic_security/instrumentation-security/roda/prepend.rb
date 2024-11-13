module NewRelic::Security
  module Instrumentation
    module Roda
      module Prepend
        include NewRelic::Security::Instrumentation::Roda

        def _roda_handle_main_route(*args)
          retval = nil
          event = _roda_handle_main_route_on_enter(env) do
            begin
              retval = super
            ensure
              NewRelic::Security::Agent.agent.error_reporting&.report_unhandled_or_5xx_exceptions(NewRelic::Security::Agent::Control::HTTPContext.get_current_transaction, NewRelic::Security::Agent::Control::HTTPContext.get_context, nil)
            end
          end
          _roda_handle_main_route_on_exit(event, retval) { return retval }
        end
        
      end
    end
  end
end