require 'thread'

module NewRelic::Security
  module Agent
    module Control
      EVENT_QUEUE_SIZE = 10_000
      HEALTH_INTERVAL = 300
      ERROR_REPORTING_INTERVAL = 30

      class EventProcessor

        attr_accessor :eventQ, :event_dequeue_threads, :healthcheck_thread

        def initialize
          @first_event = true
          @eventQ = ::SizedQueue.new(EVENT_QUEUE_SIZE)
          create_dequeue_threads
          create_keep_alive_thread
          create_error_reporting_thread
          NewRelic::Security::Agent.init_logger.info "[STEP-5] => Security agent components started"
        end

        def send_app_info
          NewRelic::Security::Agent.init_logger.info "[STEP-3] => Gathering information about the application"
          app_info = NewRelic::Security::Agent::Control::AppInfo.new
          app_info.update_app_info
          NewRelic::Security::Agent.logger.info "Sending application info : #{app_info.to_json}"
          NewRelic::Security::Agent.init_logger.info "Sending application info : #{app_info.to_json}"
          # enqueue(app_info)
          app_info = nil
        end

        def send_application_url_mappings
          application_url_mappings = NewRelic::Security::Agent::Control::ApplicationURLMappings.new
          application_url_mappings.update_application_url_mappings
          NewRelic::Security::Agent.logger.info "Sending application URL Mappings : #{application_url_mappings.to_json}"
          # enqueue(application_url_mappings)
          application_url_mappings = nil
        end

        def send_event(event)
          NewRelic::Security::Agent.agent.event_processed_count.increment
          if NewRelic::Security::Agent::Utils.is_IAST_request?(event.httpRequest[:headers])
            NewRelic::Security::Agent.agent.iast_event_stats.processed.increment
          else
            NewRelic::Security::Agent.agent.rasp_event_stats.processed.increment
          end
          # enqueue(event)
          if @first_event
            NewRelic::Security::Agent.init_logger.info "[STEP-8] => First event sent for validation. Security agent started successfully : #{event.to_json}"
            NewRelic::Security::Agent.config.traffic_start_time = current_time_millis unless NewRelic::Security::Agent.config[:traffic_start_time]
            @first_event = false
          end
          event = nil
        end

        def send_health
          health = NewRelic::Security::Agent::Control::Health.new
          health.update_health_check
          NewRelic::Security::Agent.logger.info "Sending healthcheck : #{health.to_json}"
          # NewRelic::Security::Agent::Control::WebsocketClient.instance.send(health)
          health = nil
        end

        def send_critical_message(message, level, caller, thread_name, exc)
          if exc
            exception = {}
            exception[:message] = exc.message
            exception[:cause] = { :message => exc.cause }
            exception[:stackTrace] = exc.backtrace.map(&:to_s)
          end
          critical_message = NewRelic::Security::Agent::Control::CriticalMessage.new(message, level, caller, thread_name, exception)
          # enqueue(critical_message)
          critical_message = nil
        end

        def send_exit_event(exit_event)
          NewRelic::Security::Agent.agent.exit_event_stats.processed.increment
          enqueue(exit_event)
          exit_event = nil
        end

        def send_iast_data_transfer_request(iast_data_transfer_request)
          enqueue(iast_data_transfer_request)
          iast_data_transfer_request = nil
        end

        private

        def create_dequeue_threads
          @event_dequeue_threads = []
          3.times do |t|
            @event_dequeue_threads<< Thread.new do
              Thread.current.name = "newrelic_security_event_thread-#{t}"
              loop do
                begin
                  data_to_be_sent = @eventQ.pop
                  # NewRelic::Security::Agent::Control::WebsocketClient.instance.send(data_to_be_sent)
                rescue => exception
                  NewRelic::Security::Agent.logger.error "Exception in event pop operation : #{exception.inspect}"
                end
              end
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event queue creation : #{exception.inspect}"
        end

        def enqueue(message)
          @eventQ.push(message, true)
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event enqueue, #{exception.inspect}, Dropping message"
          if message.jsonName == :Event
            NewRelic::Security::Agent.agent.event_drop_count.increment
            if NewRelic::Security::Agent::Utils.is_IAST_request?(message.httpRequest[:headers])
              NewRelic::Security::Agent.agent.iast_event_stats.rejected.increment
            else
              NewRelic::Security::Agent.agent.rasp_event_stats.rejected.increment
            end
          end
          NewRelic::Security::Agent.agent.exit_event_stats.rejected.increment if message.jsonName == :'exit-event'
          NewRelic::Security::Agent.agent.iast_client.completed_requests.delete(message.parentId)
        end

        def create_keep_alive_thread
          @healthcheck_thread = Thread.new {
            Thread.current.name = "newrelic_security_healthcheck_thread"
            while true do 
              sleep HEALTH_INTERVAL
              NewRelic::Security::Agent.logger.info "EventQ size : #{NewRelic::Security::Agent.agent.event_processor.eventQ.size}"
              send_health if NewRelic::Security::Agent::Control::WebsocketClient.instance.is_open?
            end
          }
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in health check thread, #{exception.inspect}"
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def create_error_reporting_thread
          @error_reporting_thread = Thread.new {
            Thread.current.name = "newrelic_security_error_reporting_thread"
            while true do
              sleep ERROR_REPORTING_INTERVAL
              send_error_reporting_event if NewRelic::Security::Agent::Control::WebsocketClient.instance.is_open?
            end
          }
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in error_reporting thread, #{exception.inspect}"
        end

        def send_error_reporting_event
          NewRelic::Security::Agent.agent.error_reporting&.exceptions_map&.each_value do |exception|
            NewRelic::Security::Agent::Control::WebsocketClient.instance.send(exception)
          end
          NewRelic::Security::Agent.agent.error_reporting&.exceptions_map&.clear
        end

      end
    end
  end
end