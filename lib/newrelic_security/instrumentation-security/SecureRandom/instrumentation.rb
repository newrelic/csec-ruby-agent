require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module SecureRandomClass
      
      def gen_random_on_enter
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        event = NewRelic::Security::Agent::Control::Collector.collect(RANDOM, [self.inspect], SECURERANDOM)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def gen_random_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end
    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:random, ::SecureRandom.singleton_class, ::NewRelic::Security::Instrumentation::SecureRandomClass) unless NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.insecure_settings']
