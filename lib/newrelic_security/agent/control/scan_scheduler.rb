module NewRelic::Security
  module Agent
    module Control
      class ScanScheduler
        def init_via_scan_scheduler
          if NewRelic::Security::Agent.config[:'security.scan_schedule.delay'].positive?
            NewRelic::Security::Agent.logger.info "IAST delay is set to: #{NewRelic::Security::Agent.config[:'security.scan_schedule.delay']}, current time: #{Time.now}"
            start_agent_with_delay(NewRelic::Security::Agent.config[:'security.scan_schedule.delay'])
          elsif !NewRelic::Security::Agent.config[:'security.scan_schedule.schedule'].to_s.empty?
            puts "In ScanScheduler schedule check"
          else
            NewRelic::Security::Agent.agent.init
            shutdown_at_duration_reached(NewRelic::Security::Agent.config[:'security.scan_schedule.duration'], 0)
          end
        end

        def start_agent_with_delay(delay)
          if NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']
            NewRelic::Security::Agent.logger.info "Security Agent delay scan time is set to: #{delay} minutes when always_sample_traces is true, current time: #{Time.now}"
            NewRelic::Security::Agent.agent.init
            shutdown_at_duration_reached(NewRelic::Security::Agent.config[:'security.scan_schedule.duration'], delay)
          else
            NewRelic::Security::Agent.logger.info "Security Agent delay scan time is set to: #{delay} minutes, current time: #{Time.now}"
            sleep delay * 60
            NewRelic::Security::Agent.agent.init
            shutdown_at_duration_reached(NewRelic::Security::Agent.config[:'security.scan_schedule.duration'], 0)
          end
        end

        def shutdown_at_duration_reached(duration, delay)
          shutdown_at = Time.now.to_i + (duration * 60) + (delay * 60)
          return if duration <= 0
          NewRelic::Security::Agent.logger.info "IAST Duration is set to: #{duration} minutes with delay #{delay} minutes, timestamp: #{shutdown_at} time, current time: #{Time.now}"
          @shutdown_monitor_thread = Thread.new do
            Thread.current.name = "newrelic_security_shutdown_monitor_thread"
            loop do
              sleep 1
              next if Time.now.to_i < shutdown_at
              NewRelic::Security::Agent.logger.info "Shutdown IAST agent now at current time: #{Time.now}"
              NewRelic::Security::Agent.agent.iast_client&.fuzzQ&.clear
              NewRelic::Security::Agent.agent.iast_client&.completed_requests&.clear
              NewRelic::Security::Agent.agent.iast_client&.pending_request_ids&.clear
              NewRelic::Security::Agent.agent.iast_client&.iast_data_transfer_request_processor_thread&.kill
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