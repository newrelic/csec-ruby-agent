require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Padrino::PathRouter::Router

      def call_on_enter(env)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        return unless NewRelic::Security::Agent.config[:enabled]
        NewRelic::Security::Agent.config.update_port = NewRelic::Security::Agent::Utils.app_port(env) unless NewRelic::Security::Agent.config[:listen_port]
        NewRelic::Security::Agent::Utils.get_app_routes(:padrino, self) if NewRelic::Security::Agent.agent.route_map.empty?
        extracted_env = env.instance_variable_get(:@env)
        NewRelic::Security::Agent::Control::HTTPContext.set_context(extracted_env)
        ctxt = NewRelic::Security::Agent::Control::HTTPContext.get_context
        ctxt.route = "#{extracted_env[REQUEST_METHOD]}@#{extracted_env[PATH_INFO]}" if ctxt
        NewRelic::Security::Agent::Utils.parse_fuzz_header(NewRelic::Security::Agent::Control::HTTPContext.get_context)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def call_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        # NewRelic::Security::Agent.logger.debug "\n\nHTTP Context : #{::NewRelic::Agent::Tracer.current_transaction.instance_variable_get(:@security_context_data).inspect}\n\n"
        NewRelic::Security::Agent::Control::ReflectedXSS.check_xss(NewRelic::Security::Agent::Control::HTTPContext.get_context, retval) if NewRelic::Security::Agent.config[:'security.detection.rxss.enabled']
        NewRelic::Security::Agent::Utils.delete_created_files(NewRelic::Security::Agent::Control::HTTPContext.get_context)
        NewRelic::Security::Agent.agent.error_reporting&.report_unhandled_or_5xx_exceptions(NewRelic::Security::Agent::Control::HTTPContext.get_current_transaction, NewRelic::Security::Agent::Control::HTTPContext.get_context, retval[0])
        NewRelic::Security::Agent::Control::HTTPContext.reset_context
        NewRelic::Security::Agent.logger.debug "Exit event : #{event}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end
    end

    module Padrino::Router
      def call_on_exit(retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent.agent.error_reporting&.report_unhandled_or_5xx_exceptions(NewRelic::Security::Agent::Control::HTTPContext.get_current_transaction, NewRelic::Security::Agent::Control::HTTPContext.get_context, retval[0])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end
    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:padrino, ::Padrino::PathRouter::Router, ::NewRelic::Security::Instrumentation::Padrino::PathRouter::Router)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:padrino, ::Padrino::Router, ::NewRelic::Security::Instrumentation::Padrino::Router)
