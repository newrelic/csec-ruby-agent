require 'thread'

module NewRelic::Security
  module Agent
    module Control
      EVENT_QUEUE_SIZE = 1000
      HEALTH_INTERVAL = 300

      class EventProcessor

        attr_accessor :eventQ

        def initialize
          @eventQ = ::SizedQueue.new(EVENT_QUEUE_SIZE)
          create_dequeue_threads
          create_keep_alive_thread
        end

        def send_app_info
          app_info = NewRelic::Security::Agent::Control::AppInfo.new
          app_info.update_app_info
          NewRelic::Security::Agent.logger.info "[INITIALIZATION] Sending application info : #{app_info.to_json}"
          NewRelic::Security::Agent.init_logger.info "[INITIALIZATION] Sending application info : #{app_info.to_json}"
          enqueue(app_info)
          app_info = nil
        end

        def send_event(event)
          NewRelic::Security::Agent.agent.event_processed_count.increment
          enqueue(event)
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

        private

        def create_dequeue_threads
          # TODO: Create 3 or more consumers for event sending
          Thread.new do
            loop do
              NewRelic::Security::Agent.agent.websocket_client.send(@eventQ.pop) if NewRelic::Security::Agent.agent.websocket_client && NewRelic::Security::Agent.agent.websocket_client.is_open?
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
          Thread.new {
            while true do 
              sleep HEALTH_INTERVAL
              send_health
            end
          }
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in health check thread, #{exception.inspect}"
        end

      end
    end
  end
end