require 'thread'

module NewRelic::Security
  module Agent
    module Control
      EVENT_QUEUE_SIZE = 10_000
      HEALTH_INTERVAL = 300

      class EventProcessor

        attr_accessor :eventQ, :event_dequeue_thread, :healthcheck_thread

        def initialize
          @first_event = true
          @eventQ = ::SizedQueue.new(EVENT_QUEUE_SIZE)
          create_dequeue_threads
          create_keep_alive_thread
          NewRelic::Security::Agent.init_logger.info "[STEP-5] => Security agent components started"
        end

        def send_app_info
          NewRelic::Security::Agent.init_logger.info "[STEP-3] => Gathering information about the application"
          app_info = NewRelic::Security::Agent::Control::AppInfo.new
          app_info.update_app_info
          NewRelic::Security::Agent.logger.info "Sending application info : #{app_info.to_json}"
          NewRelic::Security::Agent.init_logger.info "Sending application info : #{app_info.to_json}"
          enqueue(app_info)
          app_info = nil
        end

        def send_event(event)
          NewRelic::Security::Agent.agent.event_processed_count.increment
          enqueue(event)
          if @first_event
            NewRelic::Security::Agent.init_logger.info "[STEP-8] => First event sent for validation. Security agent started successfully : #{event.to_json}"
            @first_event = false
          end
          event = nil
        end

        def send_health
          health = NewRelic::Security::Agent::Control::Health.new
          health.update_health_check
          NewRelic::Security::Agent.agent.status_logger.add_healthcheck_in_last_healthchecks(health)
          NewRelic::Security::Agent.agent.status_logger.create_snapshot
          enqueue(health)
          health = nil
        end

        def send_exit_event(exit_event)
          enqueue(exit_event)
          exit_event = nil
        end

        def send_fuzz_fail_event(fuzz_fail_event)
          enqueue(fuzz_fail_event)
          fuzz_fail_event = nil
        end

        def send_iast_data_transfer_request(iast_data_transfer_request)
          enqueue(iast_data_transfer_request)
          iast_data_transfer_request = nil
        end

        private

        def create_dequeue_threads
          # TODO: Create 3 or more consumers for event sending
          @event_dequeue_thread = Thread.new do
            Thread.current.name = "newrelic_security_event_thread"
            loop do
              begin
                data_to_be_sent = @eventQ.pop
                NewRelic::Security::Agent::Control::WebsocketClient.instance.send(data_to_be_sent)
              rescue => exception
                NewRelic::Security::Agent.logger.error "Exception in event pop operation : #{exception.inspect}"
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
          NewRelic::Security::Agent.agent.event_drop_count.increment if message.jsonName == :Event
        end

        def create_keep_alive_thread
          @healthcheck_thread = Thread.new {
            Thread.current.name = "newrelic_security_healthcheck_thread"
            while true do 
              sleep HEALTH_INTERVAL
              send_health if NewRelic::Security::Agent.config[:enabled]
            end
          }
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in health check thread, #{exception.inspect}"
        end

      end
    end
  end
end