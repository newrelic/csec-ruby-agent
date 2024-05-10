require 'newrelic_security/instrumentation-security/instrumentation_utils'

module NewRelic::Security
  module Instrumentation
    module InstrumentationLoader
      extend self
      def add_instrumentation()
        res = ::NewRelic::Agent.add_instrumentation("#{__dir__}/**/instrumentation.rb")
        NewRelic::Security::Agent.logger.debug "res, res.class #{res.class} #{res.inspect}"
        NewRelic::Security::Agent.logger.debug "Logger print from add instrumentation api."
        NewRelic::Security::Agent.logger.debug "Agent.agent : #{NewRelic::Security::Agent.agent.inspect}"
        NewRelic::Security::Agent.logger.debug "Agent.config : #{NewRelic::Security::Agent::Utils.filtered_log(NewRelic::Security::Agent.config.inspect)}"
        NewRelic::Security::Agent.init_logger.info "[STEP-6] => Application instrumentation applied successfully"
      end

      def install_instrumentation(supportability_name, target_class, instrumenting_module)
        s_name = "instrumentation.#{supportability_name}".to_sym
        if ::NewRelic::Agent.config[s_name] == :disabled || ::NewRelic::Agent.config[s_name] == 'disabled'
          NewRelic::Security::Agent.logger.info "Skipping New Relic supported #{target_class} instrumentation, as #{s_name} is #{::NewRelic::Agent.config[s_name]}"
          NewRelic::Security::Agent.init_logger.info "Skipping New Relic supported #{target_class} instrumentation, as #{s_name} is #{::NewRelic::Agent.config[s_name]}"
        elsif ::NewRelic::Agent.config[s_name] == :chain || ::NewRelic::Agent.config[s_name] == 'chain'
          NewRelic::Security::Instrumentation::InstrumentationLoader.chain_instrument target_class, Object.const_get("#{instrumenting_module}::Chain")
        else
          NewRelic::Security::Instrumentation::InstrumentationLoader.prepend_instrument target_class, Object.const_get("#{instrumenting_module}::Prepend")
        end
      end

      def log_and_instrument(method, target_class, instrumenting_module, supportability_name)
        # supportability_name ||= extract_supportability_name(instrumenting_module)
        puts "Installing New Relic supported #{target_class} instrumentation using #{method}"
        NewRelic::Security::Agent.logger.info "Installing New Relic supported #{target_class} instrumentation using #{method}"
        NewRelic::Security::Agent.logger.info "Supportability/Instrumentation/#{target_class}/#{method}"
        NewRelic::Security::Agent.init_logger.info "Installing New Relic supported #{target_class} instrumentation using #{method}"
        yield
      end

      def prepend_instrument(target_class, instrumenting_module, supportability_name = nil)
        log_and_instrument('Prepend', target_class, instrumenting_module, supportability_name) do
          target_class.send(:prepend, instrumenting_module)
        end
      end
  
      def chain_instrument(target_class, instrumenting_module, supportability_name = nil)
        log_and_instrument('MethodChaining', target_class, instrumenting_module, supportability_name) do
          instrumenting_module.instrument!
        end
      end
    end
  end
end

