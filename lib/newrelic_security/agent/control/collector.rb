# frozen_string_literal: true
require 'digest'

module NewRelic::Security
  module Agent
    module Control
      module Collector

        COVERAGE = 101
        MARSHAL_RB = 'marshal.rb'
        LOAD = 'load'
        PSYCH_RB = 'psych.rb'
        MARSHAL_LOAD = 'marshal_load'
        EVAL = 'eval'

        extend self

        def collect(case_type, args, event_category = nil, **keyword_args)
          return unless NewRelic::Security::Agent.config[:enabled]
          return if NewRelic::Security::Agent::Control::HTTPContext.get_context.nil?
          
          event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)

          stk = caller_locations[1..COVERAGE]
          event.sourceMethod = stk[0].label
          user_frame_index = get_user_frame_index(stk)
          return if case_type != REFLECTED_XSS && user_frame_index == -1 # TODO: Add log message here: "Filtered because User Stk frame NOT FOUND   \r\n"
          if user_frame_index != -1
            event.userMethodName = stk[user_frame_index].label.to_s
            event.userFileName = stk[user_frame_index].path
            event.lineNumber = stk[user_frame_index].lineno
          else
            event.userMethodName = stk[0].label
            event.userFileName = stk[1].path
            event.lineNumber = stk[1].lineno
          end

          event.copy_http_info(NewRelic::Security::Agent::Control::HTTPContext.get_context)
          event.isIASTEnable = true if NewRelic::Security::Agent::Utils.is_IAST?
          event.isIASTRequest = true if NewRelic::Security::Agent::Utils.is_IAST_request?(event.httpRequest[:headers])
          find_deserialisation(event, stk) if case_type != REFLECTED_XSS && NewRelic::Security::Agent.config[:'security.detection.deserialization.enabled']
          find_rci(event, stk) if case_type != REFLECTED_XSS && NewRelic::Security::Agent.config[:'security.detection.rci.enabled']
          event.stacktrace = stk[0..user_frame_index].map(&:to_s)
          if case_type == REFLECTED_XSS
            route = NewRelic::Security::Agent::Control::HTTPContext.get_context.route
            if route && NewRelic::Security::Agent.agent.route_map.include?(route)
              event.stacktrace << route
            end
          end
          event.apiId = calculate_api_id(event.stacktrace, event.httpRequest[:method])
          NewRelic::Security::Agent.agent.event_processor.send_event(event)
          event
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event collector: #{exception.inspect} #{exception.backtrace}"
        end

        private

        def get_user_frame_index(stk)
          return -1 if NewRelic::Security::Agent.config[:app_root].nil?
          stk.each_with_index do |val, index|
            return index if val.path.start_with?(NewRelic::Security::Agent.config[:app_root])
          end
          return -1
        end

        def calculate_api_id(stk, method)
          ::Digest::SHA256.hexdigest("#{stk.join(PIPE)}|#{method}").to_s
        rescue Exception => e
          NewRelic::Security::Agent.logger.error "Exception in calculate_api_id : #{e} #{e.backtrace}"
          nil
        end

        def find_deserialisation(event, stk)
          stk.each_with_index { |val, index|
            if (val.path.end_with?(MARSHAL_RB) && val.label == LOAD) || (val.path.end_with?(PSYCH_RB) && val.label == LOAD) || (val.label == MARSHAL_LOAD)
              event.metaData[:triggerViaDeserialisation] = true
              event.metaData[:rciMethodsCalls] = stk[0..index].collect { |frame| frame.label }
              return
            end
          }
        end

        def find_rci(event, stk)
          stk.each_with_index { |val, index|
            if val.label == EVAL
              event.metaData[:triggerViaRCI] = true
              event.metaData[:rciMethodsCalls] = stk[0..index].collect { |frame| frame.label }
              return
            end
          }
        end

      end
    end
  end
end