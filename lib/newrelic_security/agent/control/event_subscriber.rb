module NewRelic::Security
  module Agent
    module Control
      class EventSubscriber
        def initialize
            ::NewRelic::Agent.instance.events.subscribe(:server_source_configuration_added) {
              NewRelic::Security::Agent.logger.info "NewRelic server_source_configuration_added for pid : #{Process.pid}, Parent Pid : #{Process.ppid}"
              NewRelic::Security::Agent.init_logger.info "[INITIALIZATION] NewRelic server_source_configuration_added for pid : #{Process.pid}, Parent Pid : #{Process.ppid}"
              NewRelic::Security::Agent.config.update_server_config
              NewRelic::Security::Agent.logger.info "Security agent is disabled.\n" unless NewRelic::Security::Agent.config[:enabled]
              NewRelic::Security::Agent.init_logger.info "[INITIALIZATION] Security agent is disabled." unless NewRelic::Security::Agent.config[:enabled]
              NewRelic::Security::Agent.agent.init if NewRelic::Security::Agent.config[:enabled]
            }
            ::NewRelic::Agent.instance.events.subscribe(:security_policy_received) { |received_policy| 
              NewRelic::Security::Agent.logger.info "security_policy_received pid ::::::: #{Process.pid} #{Process.ppid}, #{received_policy}"
              NewRelic::Security::Agent.init_logger.info "[INITIALIZATION] security_policy_received pid ::::::: #{Process.pid} #{Process.ppid}, #{received_policy}"
              NewRelic::Security::Agent.config[:policy].merge!(received_policy)
              NewRelic::Security::Agent.agent.start_iast_client if NewRelic::Security::Agent::Utils.is_IAST?
            }
        end
      end
    end
  end
end

