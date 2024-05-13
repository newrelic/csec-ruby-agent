# Instrumentation config
module NewRelic::Security
  module Instrumentation
    module InstrumentationLoader
      extend self
      def install_instrumentation(supportability_name, target_class, instrumenting_module)
        s_name = "instrumentation.#{supportability_name}".to_sym
        if ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == :disabled || ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == 'disabled'
          NewRelic::Security::Agent.logger.info "Skipping New Relic supported #{target_class} instrumentation, as #{s_name} is #{ENV['NR_CSEC_INSTRUMENTATION_METHOD']}"
        elsif ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == :chain || ENV['NR_CSEC_INSTRUMENTATION_METHOD'] == 'chain'
          NewRelic::Security::Instrumentation::InstrumentationLoader.chain_instrument target_class, Object.const_get("#{instrumenting_module}::Chain")
        else
          NewRelic::Security::Instrumentation::InstrumentationLoader.prepend_instrument target_class, Object.const_get("#{instrumenting_module}::Prepend")
        end
      end
    end
  end
end