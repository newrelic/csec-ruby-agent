require 'newrelic_security/parse-cron/cron_parser'

module NewRelic::Security
  module Agent
    module Control
      class ScanScheduler
        def init_via_scan_scheduler
          if NewRelic::Security::Agent.config[:'security.scan_schedule.delay'].positive?
            NewRelic::Security::Agent.logger.info "IAST delay is set to: #{NewRelic::Security::Agent.config[:'security.scan_schedule.delay']}, current time: #{Time.now}"
            start_agent_with_delay(NewRelic::Security::Agent.config[:'security.scan_schedule.delay']*60)
          elsif !NewRelic::Security::Agent.config[:'security.scan_schedule.schedule'].to_s.empty?
            cron_expression_task(NewRelic::Security::Agent.config[:'security.scan_schedule.schedule'], NewRelic::Security::Agent.config[:'security.scan_schedule.duration']*60)
          else
            NewRelic::Security::Agent.agent.init
            NewRelic::Security::Agent.agent.start_iast_client if NewRelic::Security::Agent::Utils.is_IAST?
            shutdown_at_duration_reached(NewRelic::Security::Agent.config[:'security.scan_schedule.duration']*60)
          end
        rescue StandardError => exception
          NewRelic::Security::Agent.logger.error "Exception in IAST scan scheduler: #{exception.inspect} #{exception.backtrace}"
          ::NewRelic::Agent.notice_error(exception)
        end

        def start_agent_with_delay(delay)
          NewRelic::Security::Agent.logger.info "Security Agent delay scan time is set to: #{(delay/60).ceil} minutes when always_sample_traces is #{NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']}, current time: #{Time.now}"
          if NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']
            NewRelic::Security::Agent.agent.init
            sleep delay if NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']
          else
            sleep delay
            NewRelic::Security::Agent.agent.init
          end
          NewRelic::Security::Agent.agent.start_iast_client if NewRelic::Security::Agent::Utils.is_IAST?
          shutdown_at_duration_reached(NewRelic::Security::Agent.config[:'security.scan_schedule.duration']*60)
        end

        def shutdown_at_duration_reached(duration)
          shutdown_at = Time.now.to_i + duration
          shut_down_time = (Time.now + duration).strftime("%a %d %b %Y %H:%M:%S")
          return if duration <= 0
          NewRelic::Security::Agent.logger.info "IAST Duration is set to: #{duration/60} minutes, timestamp: #{shut_down_time} time, current time: #{Time.now}"
          @shutdown_monitor_thread = Thread.new do
            Thread.current.name = "newrelic_security_shutdown_monitor_thread"
            loop do
              sleep 1
              next if Time.now.to_i < shutdown_at
              if NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']
                NewRelic::Security::Agent.logger.info "Shutdown IAST Data transfer request processor only as 'security.scan_schedule.always_sample_traces' is #{NewRelic::Security::Agent.config[:'security.scan_schedule.always_sample_traces']} now at current time: #{Time.now}"
                NewRelic::Security::Agent.agent.iast_client&.iast_data_transfer_request_processor_thread&.kill
              else
                NewRelic::Security::Agent.logger.info "Shutdown IAST agent now at current time: #{Time.now}"
                ::NewRelic::Agent.notice_error(StandardError.new("WS Connection closed by local"))
                NewRelic::Security::Agent.agent.shutdown_security_agent
              end
              break
            end
          end
        end

        def cron_expression_task(schedule, duration)
          @cron_parser = NewRelic::Security::ParseCron::CronParser.new(schedule)
          loop do
            next_run = @cron_parser.next(Time.now)
            NewRelic::Security::Agent.logger.info "Next init via cron exp: #{schedule},  is scheduled at : #{next_run}"
            delay = next_run - Time.now
            start_agent_with_delay(delay) unless NewRelic::Security::Agent.agent.iast_client&.iast_data_transfer_request_processor_thread&.alive?
            return if duration <= 0
          end
        end
        
      end
    end
  end
end