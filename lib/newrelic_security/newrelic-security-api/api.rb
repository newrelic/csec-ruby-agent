module NewRelic::Security
  #
  # This module contains most of the public API methods for the Ruby Security Agent.
  #
  # @api public
  # 
  module API

    #
    # Check whether security is enabled
    #
    # @return [Boolean] true if security is enabled else false
    #
    # @api public
    # 
    def is_security_active?
      NewRelic::Security::Agent.config[:'agent.enabled'] && NewRelic::Security::Agent.config[:'security.enabled'] && NewRelic::Security::Agent.config[:enabled]
    end

    #
    # Manually initializes the security agent
    #
    # @param [Hash] Unused options Hash
    #
    # @return [nil] 
    # 
    # @api public
    #
    def manual_start(options = {})
      raise "Options must be a hash" unless Hash === options
      NewRelic::Security::Agent.config.enable_security
      NewRelic::Security::Agent.agent.init
    end

    #
    # Deactivates security and stops sending events to security engine
    #
    # @return [nil]
    #
    # @api public
    # 
    def deactivate_security
      NewRelic::Security::Agent.config.disable_security
    end

    #
    # Send and event to security engine
    #
    # @param [NewRelic::Security::Agent::Control::Event] event IAST event to be sent to validator
    #
    # @return [nil] 
    # 
    # @api public
    #
    def send_event(event)
      NewRelic::Security::Agent.agent.event_processor.send_event(event)
    end
    
    #
    # Send and exit event to security engine
    #
    # @param [NewRelic::Security::Agent::Control::ExitEvent] exit_event IAST exit event for api call to be sent to validator
    #
    # @return [nil] 
    # 
    # @api public
    #
    def send_exit_event(exit_event)
      NewRelic::Security::Agent.agent.event_processor.send_exit_event(exit_event)
    end
  end
end