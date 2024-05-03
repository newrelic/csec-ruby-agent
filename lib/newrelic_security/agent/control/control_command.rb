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
              NewRelic::Security::Agent.agent.iast_client.last_fuzz_cc_timestamp = current_time_millis
              fuzz_request = NewRelic::Security::Agent::Control::FuzzRequest.new(message_object[:id])
              fuzz_request.request = prepare_fuzz_request(message_object)
              fuzz_request.case_type = message_object[:arguments][1]
              fuzz_request.reflected_metadata =  message_object[:reflectedMetaData]
              NewRelic::Security::Agent.agent.iast_client.pending_request_ids << message_object[:id]
              NewRelic::Security::Agent.agent.iast_client.enqueue(fuzz_request)
              fuzz_request = nil
            when 12
              NewRelic::Security::Agent.logger.info "Validator asked to reconnect(CC#12), calling reconnect_at_will"
              reconnect_at_will
            when 13
              NewRelic::Security::Agent.logger.debug "Control command : '13', #{message_object}"
              NewRelic::Security::Agent.logger.debug "Received IAST cooldown. Waiting for next : #{message_object[:data]} Seconds"
              NewRelic::Security::Agent.agent.iast_client.cooldown_till_timestamp = current_time_millis + (message_object[:data] * 1000)
            when 14
              NewRelic::Security::Agent.logger.debug "Control command : '14', #{message_object}"
              NewRelic::Security::Agent.logger.debug "Purging confirmed IAST processed records count : #{message_object[:arguments].size}"
              message_object[:arguments].each { |processed_id| NewRelic::Security::Agent.agent.iast_client.completed_requests.delete(processed_id) }
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
          NewRelic::Security::Agent.agent.event_processor.send_critical_message(exception.message, "SEVERE", caller_locations[0].to_s, Thread.current.name, exception)
          nil
        end

        def reconnect_at_will
          NewRelic::Security::Agent.agent.iast_client.fuzzQ.clear
          NewRelic::Security::Agent.agent.iast_client.completed_requests.clear
          NewRelic::Security::Agent.agent.iast_client.pending_request_ids.clear
          NewRelic::Security::Agent.config.disable_security
          Thread.new { NewRelic::Security::Agent.agent.reconnect(0) }
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def prepare_fuzz_request(message_object)
          message_object[:arguments][0].gsub!(NR_CSEC_VALIDATOR_HOME_TMP, NR_SECURITY_HOME_TMP)
          message_object[:arguments][0].gsub!(NR_CSEC_VALIDATOR_FILE_SEPARATOR, ::File::SEPARATOR)
          prepared_fuzz_request = ::JSON.parse(message_object[:arguments][0])
          prepared_fuzz_request[HEADERS][NR_CSEC_PARENT_ID] = message_object[:id]
          prepared_fuzz_request
        rescue Exception => exception # rubocop:disable Lint/RescueException
          NewRelic::Security::Agent.logger.error "Exception in preparing fuzz request : #{exception.inspect} #{exception.backtrace}"
        end
      end
    end
  end
end