# frozen_string_literal: true
require 'digest'
require 'pathname'

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
          return if NewRelic::Security::Agent::Control::HTTPContext.get_context.nil? && NewRelic::Security::Agent::Control::GRPCContext.get_context.nil?
          return if check_and_exclude_from_iast_scan_for_api
          return if check_and_exclude_from_iast_scan_for_detection_category(case_type)
          args.map! { |file| Pathname.new(file).relative? ? File.join(Dir.pwd, file) : file } if [FILE_OPERATION, FILE_INTEGRITY].include?(case_type)

          event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
          stk = caller_locations[1..COVERAGE]
          event.sourceMethod = stk[0].label

          event.copy_http_info(NewRelic::Security::Agent::Control::HTTPContext.get_context) if NewRelic::Security::Agent::Control::HTTPContext.get_context
          event.copy_grpc_info(NewRelic::Security::Agent::Control::GRPCContext.get_context) if NewRelic::Security::Agent::Control::GRPCContext.get_context
          event.isIASTEnable = true if NewRelic::Security::Agent::Utils.is_IAST?
          event.isIASTRequest = true if NewRelic::Security::Agent::Utils.is_IAST_request?(event.httpRequest[:headers])
          event.parentId = event.httpRequest[:headers][NR_CSEC_PARENT_ID] if event.httpRequest[:headers].key?(NR_CSEC_PARENT_ID)
          find_deserialisation(event, stk) if case_type != REFLECTED_XSS && NewRelic::Security::Agent.config[:'security.detection.deserialization.enabled']
          find_rci(event, stk) if case_type != REFLECTED_XSS && NewRelic::Security::Agent.config[:'security.detection.rci.enabled']
          route = nil
          if case_type == REFLECTED_XSS
            event.httpResponse[:contentType] = keyword_args[:response_header]
            route = NewRelic::Security::Agent::Control::HTTPContext.get_context.route
            if route && NewRelic::Security::Agent.agent.route_map.include?(route)
              event.stacktrace << route
            end
          end
          # In rails 5 method name keeps chaning for same api call (ex: _app_views_sqli_sqlinjectionattackcase_html_erb__1999281606898621405_2624809100).
          # Hence, considering only frame absolute_path & lineno for apiId calculation.
          user_frame_index = get_user_frame_index(stk)
          event.apiId = "#{case_type}-#{calculate_api_id(stk[0..user_frame_index].map { |frame| "#{frame.absolute_path}:#{frame.lineno}" }, event.httpRequest[:method], route&.gsub(/\d+$/, EMPTY_STRING))}"
          stk.delete_if { |frame| frame.path.match?(/newrelic_security/) || frame.path.match?(/new_relic/) }
          user_frame_index = get_user_frame_index(stk)
          return if case_type != REFLECTED_XSS && user_frame_index == -1 # TODO: Add log message here: "Filtered because User Stk frame NOT FOUND   \r\n"
          if user_frame_index != -1
            event.userMethodName = stk[user_frame_index].label.to_s
            event.userFileName = stk[user_frame_index].path
            event.lineNumber = stk[user_frame_index].lineno
          else
            event.sourceMethod = stk[0].label.to_s
            event.userMethodName = stk[0].label.to_s
            event.userFileName = stk[0].path
            event.lineNumber = stk[0].lineno
          end
          event.stacktrace = stk[0..user_frame_index].map(&:to_s)
          NewRelic::Security::Agent.agent.event_processor&.send_event(event)
          if event.httpRequest[:headers].key?(NR_CSEC_FUZZ_REQUEST_ID) && event.apiId == event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID].split(COLON_IAST_COLON)[0] && NewRelic::Security::Agent.agent.iast_client.completed_requests[event.parentId]
            NewRelic::Security::Agent.agent.iast_client.completed_requests[event.parentId] << event.id
          end
          event
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event collector: #{exception.inspect} #{exception.backtrace}"
          NewRelic::Security::Agent.agent.event_processor.send_critical_message(exception.message, "SEVERE", caller_locations[0].to_s, Thread.current.name, exception)
          if NewRelic::Security::Agent::Utils.is_IAST_request?(event.httpRequest[:headers])
            NewRelic::Security::Agent.agent.iast_event_stats.error_count.increment
          else
            NewRelic::Security::Agent.agent.rasp_event_stats.error_count.increment
          end
        ensure
          event = nil
          stk = nil
          route = nil
        end

        private

        def get_user_frame_index(stk)
          return -1 if NewRelic::Security::Agent.config[:app_root].nil?
          stk.each_with_index do |val, index|
            return index if val.path.start_with?(NewRelic::Security::Agent.config[:app_root])
          end
          return -1
        end

        def calculate_api_id(stk, method, route)
          stk << route if route
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

        def check_and_exclude_from_iast_scan_for_api
          NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.api'].each do |api|
            return true if api&.match?(NewRelic::Security::Agent::Control::HTTPContext.get_context.url)
          end
          return false
        end

        def check_and_exclude_from_iast_scan_for_detection_category(case_type)
          case case_type
          when FILE_OPERATION, FILE_INTEGRITY
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.invalid_file_access']
          when SQL_DB_COMMAND
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.sql_injection']
          when NOSQL_DB_COMMAND
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.nosql_injection']
          when LDAP
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.ldap_injection']
          when SYSTEM_COMMAND
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.command_injection']
          when XPATH
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.xpath_injection']
          when HTTP_REQUEST
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.ssrf']
          when REFLECTED_XSS
            NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.rxss']
          else
            false
          end
        end
      end
    end
  end
end