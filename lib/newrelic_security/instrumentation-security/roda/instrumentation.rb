require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Roda

      def _roda_handle_main_route_on_enter(env)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        NewRelic::Security::Agent.config.update_port = NewRelic::Security::Agent::Utils.app_port(env) unless NewRelic::Security::Agent.config[:listen_port]
        NewRelic::Security::Agent::Utils.get_app_routes(:roda) if NewRelic::Security::Agent.agent.route_map.empty?
        NewRelic::Security::Agent::Control::HTTPContext.set_context(env)
        ctxt = NewRelic::Security::Agent::Control::HTTPContext.get_context
        ctxt.route = "#{env[REQUEST_METHOD].to_s}@#{env[PATH_INFO].to_s}" if ctxt
        NewRelic::Security::Agent::Utils.parse_fuzz_header
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def _roda_handle_main_route_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        # NewRelic::Security::Agent.logger.debug "\n\nHTTP Context : #{::NewRelic::Agent::Tracer.current_transaction.instance_variable_get(:@security_context_data).inspect}\n\n"
        NewRelic::Security::Agent::Control::ReflectedXSS.check_xss(NewRelic::Security::Agent::Control::HTTPContext.get_context, retval) if NewRelic::Security::Agent.config[:'security.detection.rxss.enabled']
        NewRelic::Security::Agent::Utils.delete_created_files
        NewRelic::Security::Agent::Control::HTTPContext.reset_context
        NewRelic::Security::Agent.logger.debug "Exit event : #{event}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end
            
    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:roda, ::Roda, ::NewRelic::Security::Instrumentation::Roda)
