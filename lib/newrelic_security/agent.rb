module NewRelic::Security
  module Agent    
    extend self

    require 'newrelic_security/constants'
    require 'newrelic_security/agent/logging/logger'
    require 'newrelic_security/agent/logging/init_logger'
    require 'newrelic_security/agent/configuration/manager'
    require 'newrelic_security/agent/agent'
    require 'newrelic_security/agent/utils/agent_utils'

    @agent = nil
    @logger = nil
    @config = nil
    @event_subscriber = nil

    # puts "NewRelic::Agent.agent : #{::NewRelic::Agent.agent.inspect}"
    # puts "NewRelic::Agent.config : #{::NewRelic::Agent.config.inspect}"
    # puts "NewRelic::Agent.config : #{::NewRelic::Agent.config.instance_variables}"

    def agent()
      return @agent if @agent
      puts "Agent unavailable as it hasn't been started."
      nil
    end

    def logger
      @logger ||= NewRelic::Security::Agent::Logging::AgentLogger.new
    end

    def logger=(log)
      @logger = log
    end

    def init_logger
      @init_logger ||= NewRelic::Security::Agent::Logging::AgentInitLogger.new
    end

    def init_logger=(log)
      @init_logger = log
    end

    def config
      @config ||= NewRelic::Security::Agent::Configuration::Manager.new
    end

    def config=(new_config)
      @config = new_config
    end
    
    @agent = NewRelic::Security::Agent::Agent.new unless @agent
    NewRelic::Agent.instance.events.notify(:server_source_configuration_added) if ::Gem.win_platform? && NewRelic::Agent.agent.connected?
    NewRelic::Security::Agent.logger.debug "Creating security agent instance initially : #{@agent.inspect}"
    NewRelic::Security::Agent.init_logger.info "[STEP-1] => Security agent is starting : #{@agent.inspect}"
    NewRelic::Security::Agent.init_logger.info "[STEP-2] => Generating unique identifier : #{@config[:uuid]}"
  end
end
