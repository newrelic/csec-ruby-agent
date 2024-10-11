module NewRelic::Security
  module Agent
    module Control
      class ScanScheduler
        def init_via_scan_scheduler
          if NewRelic::Security::Agent.config[:'security.scan_schedule.delay'].positive?
            NewRelic::Security::Agent.logger.info "IAST delay is set to: #{NewRelic::Security::Agent.config[:'security.scan_schedule.delay']}"
            puts "In ScanScheduler delay check"
            start_agent_with_delay(NewRelic::Security::Agent.config[:'security.scan_schedule.delay'] * 60)
          elsif !NewRelic::Security::Agent.config[:'security.scan_schedule.schedule'].to_s.empty?
            puts "In ScanScheduler schedule check"
          else
            puts "In ScanScheduler else case"
            NewRelic::Security::Agent.agent.init
            shutdown_at_duration_reached(0)
          end
        end

        def start_agent_with_delay(delay)
          if NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']
            puts "In start_agent_with_delay always_sample_traces check"
            NewRelic::Security::Agent.agent.init
          else
            puts "In start_agent_with_delay else case"
            puts Time.now.to_s
            NewRelic::Security::Agent.logger.info "Security Agent delay scan time is set to: #{delay}"
            sleep delay
            puts Time.now.to_s
            NewRelic::Security::Agent.agent.init
            shutdown_at_duration_reached(0)
          end
        end

        def shutdown_at_duration_reached(delta)
          duration = Time.now.to_i + delta + (NewRelic::Security::Agent.config[:'security.scan_schedule.duration'] * 60)
          NewRelic::Security::Agent.logger.info "IAST Duration is set to: #{duration}"
          return if NewRelic::Security::Agent.config[:'security.scan_schedule.duration'] <= 0
          @shutdown_monitor_thread = Thread.new do
            Thread.current.name = "newrelic_security_shutdown_monitor_thread"
            loop do
              sleep 1
              next if Time.now.to_i < duration
              puts "Shutdown now at #{Time.now} #{duration}"
              NewRelic::Security::Agent.agent.iast_client.fuzzQ.clear if NewRelic::Security::Agent.agent.iast_client
              NewRelic::Security::Agent.agent.iast_client.completed_requests.clear if NewRelic::Security::Agent.agent.iast_client
              NewRelic::Security::Agent.agent.iast_client.pending_request_ids.clear if NewRelic::Security::Agent.agent.iast_client
              NewRelic::Security::Agent.config.disable_security
              NewRelic::Security::Agent.agent.stop_websocket_client_if_open
              break
            end
          end
        end
        
      end
    end
  end
end