require 'json'

module NewRelic::Security
  module Agent
    module Control
      module ControlCommand

        extend self

        def handle_ic_command(message)
          message_json = parse_message(message)
          define_transform_keys unless message_json.respond_to?(:transform_keys)
          message_object = message_json.transform_keys(&:to_sym)
          return if message_object.nil?

          if message_object.has_key?(:controlCommand)
            case message_object[:controlCommand]
            when 4
              
            when 5
              NewRelic::Security::Agent.logger.debug "Control command : '5', #{message_object}"
            when 6

            when 7
              NewRelic::Security::Agent.logger.debug "Control command : '7', #{message_object}"
            when 10
              NewRelic::Security::Agent.logger.debug "Control command : '10', #{message_object}"
            when 11
              NewRelic::Security::Agent.logger.debug "Control command : '11', #{message_object.to_json}"
              NewRelic::Security::Agent.config.update_port = message_object[:reflectedMetaData][LISTEN_PORT].to_i unless NewRelic::Security::Agent.config[:listen_port]
              NewRelic::Security::Agent.agent.iast_client.enqueue(message_object[:arguments])
            when 12
              NewRelic::Security::Agent.logger.info "Validator asked to reconnect(CC#12), calling reconnect_at_will"
              reconnect_at_will
            when 100
              NewRelic::Security::Agent.logger.debug "Control command : '100', #{message_object.to_json}"
              ::NewRelic::Agent.instance.events.notify(:security_policy_received, message_object[:data])
              # TODO: Update policy from file here, if enabled.
            when 101

            when 102
              NewRelic::Security::Agent.logger.error "Update policy failed at validator with error : #{message_object}"
              # TODO: Apply initial policy here
            when 1006
              # TODO: abnormal closure in which case LC anyway have to reconnect
            when 1013
              # TODO: ndicates that the service is experiencing overload. A client should only connect to a different IP (when there are multiple for the target) or 	reconnect to the same IP upon user action.
            else
              NewRelic::Security::Agent.logger.error "Unrecognized control command : #{message_object}"
            end
          else
            NewRelic::Security::Agent.logger.error "Control command is missing in IC message : #{message_object}"
          end
        end

        def define_transform_keys
          ::Hash.class_eval do
            def transform_keys
              result = {}
              each_key do |key|
                result[yield(key)] = self[key]
              end
              result
            end
          end
        end

        private 

        def parse_message(message)
          JSON.parse(message)
        rescue JSON::ParserError => error
          NewRelic::Security::Agent.logger.error "Error in parsing IC message : #{error.inspect}"
          nil
        end

        def reconnect_at_will
          @stop_fuzzing = true
          if NewRelic::Security::Agent::Utils.is_IAST?
            while NewRelic::Security::Agent.agent.iast_client.fuzzQ && NewRelic::Security::Agent.agent.iast_client.fuzzQ.size > 0
              NewRelic::Security::Agent.logger.info "Waiting for fuzzQ to get empty, current size: #{NewRelic::Security::Agent.agent.iast_client.fuzzQ.size}"
              sleep 0.1
            end
          end
          NewRelic::Security::Agent.config.disable_security
          while NewRelic::Security::Agent.agent.event_processor.eventQ && NewRelic::Security::Agent.agent.event_processor.eventQ.size > 0
            NewRelic::Security::Agent.logger.info "Waiting for eventQ to get empty, current size: #{NewRelic::Security::Agent.agent.event_processor.eventQ.size}"
            sleep 0.1
          end
          Thread.new { NewRelic::Security::Agent.agent.reconnect(0) }
          NewRelic::Security::Agent::Control::WebsocketClient.instance.close
        end
        
      end
    end
  end
end