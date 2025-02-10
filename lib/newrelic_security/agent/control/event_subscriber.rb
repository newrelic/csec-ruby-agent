module NewRelic::Security
  module Agent
    module Control
      class EventSubscriber
        def initialize
            ::NewRelic::Agent.instance.events.subscribe(:server_source_configuration_added) {
              NewRelic::Security::Agent.logger.info "NewRelic server_source_configuration_added for pid : #{Process.pid}, Parent Pid : #{Process.ppid}"
              NewRelic::Security::Agent.init_logger.info "NewRelic server_source_configuration_added for pid : #{Process.pid}, Parent Pid : #{Process.ppid}"
              NewRelic::Security::Agent.config.update_server_config
              if NewRelic::Security::Agent.config[:'security.enabled'] && !NewRelic::Security::Agent.config[:high_security]
                NewRelic::Security::Agent.agent.event_processor&.event_dequeue_threads&.each { |t| t&.kill }
                NewRelic::Security::Agent.agent.event_processor = nil
                @csec_agent_main_thread&.kill
                @csec_agent_main_thread = nil
                @csec_agent_main_thread = Thread.new { NewRelic::Security::Agent.agent.scan_scheduler.init_via_scan_scheduler }
              else
                NewRelic::Security::Agent.logger.info "New Relic Security is disabled by one of the user provided config `security.enabled` or `high_security`."
                NewRelic::Security::Agent.init_logger.info "New Relic Security is disabled by one of the user provided config `security.enabled` or `high_security`."
              end
            }
        end
      end
    end
  end
end

