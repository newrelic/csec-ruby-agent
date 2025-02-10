# frozen_string_literal: true

require 'newrelic_security/websocket-client-simple/client'
require 'openssl'
require 'singleton'

module NewRelic::Security
  module Agent
    module Control

      NR_CSEC_CONNECTION_TYPE = 'NR-CSEC-CONNECTION-TYPE'
      NR_LICENSE_KEY = 'NR-LICENSE-KEY'
      NR_AGENT_RUN_TOKEN = 'NR-AGENT-RUN-TOKEN'
      NR_CSEC_VERSION = 'NR-CSEC-VERSION'
      NR_CSEC_COLLECTOR_TYPE = 'NR-CSEC-COLLECTOR-TYPE'
      NR_CSEC_BUILD_NUMBER = 'NR-CSEC-BUILD-NUMBER'
      NR_CSEC_MODE = 'NR-CSEC-MODE'
      NR_CSEC_APP_UUID = 'NR-CSEC-APP-UUID'
      NR_CSEC_JSON_VERSION = 'NR-CSEC-JSON-VERSION'
      NR_ACCOUNT_ID = 'NR-ACCOUNT-ID'
      NR_CSEC_ENTITY_NAME = 'NR-CSEC-ENTITY-NAME'
      NR_CSEC_ENTITY_GUID = 'NR-CSEC-ENTITY-GUID'
      NR_CSEC_IAST_DATA_TRANSFER_MODE = 'NR-CSEC-IAST-DATA-TRANSFER-MODE'
      NR_CSEC_IGNORED_VUL_CATEGORIES = 'NR-CSEC-IGNORED-VUL-CATEGORIES'
      NR_CSEC_PROCESS_START_TIME = 'NR-CSEC-PROCESS-START-TIME'
      NR_CSEC_IAST_SCAN_INSTANCE_COUNT = 'NR-CSEC-IAST-SCAN-INSTANCE-COUNT'
      NR_CSEC_IAST_TEST_IDENTIFIER = 'NR-CSEC-IAST-TEST-IDENTIFIER'

      class WebsocketClient
        include Singleton

        attr_accessor :ws

        def connect()

          headers = Hash.new
          headers[NR_CSEC_CONNECTION_TYPE] = LANGUAGE_COLLECTOR
          headers[NR_LICENSE_KEY] = NewRelic::Security::Agent.config[:license_key]
          headers[NR_AGENT_RUN_TOKEN] = NewRelic::Security::Agent.config[:agent_run_id]
          headers[NR_CSEC_VERSION] = NewRelic::Security::VERSION
          headers[NR_CSEC_COLLECTOR_TYPE] = RUBY
          headers[NR_CSEC_BUILD_NUMBER] = '0000'
          headers[NR_CSEC_MODE] = NewRelic::Security::Agent.config[:mode]
          headers[NR_CSEC_APP_UUID] = NewRelic::Security::Agent.config[:uuid]
          headers[NR_CSEC_JSON_VERSION] = NewRelic::Security::Agent.config[:json_version]
          headers[NR_ACCOUNT_ID] = NewRelic::Security::Agent.config[:account_id]
          headers[NR_CSEC_ENTITY_NAME] = NewRelic::Security::Agent.config[:app_name]
          headers[NR_CSEC_ENTITY_GUID] = NewRelic::Security::Agent.config[:entity_guid]
          headers[NR_CSEC_IAST_DATA_TRANSFER_MODE] = PULL
          headers[NR_CSEC_IGNORED_VUL_CATEGORIES] = ingnored_vul_categories.join(COMMA)
          headers[NR_CSEC_PROCESS_START_TIME] = NewRelic::Security::Agent.config[:process_start_time]
          headers[NR_CSEC_IAST_SCAN_INSTANCE_COUNT] = NewRelic::Security::Agent.config[:'security.scan_controllers.scan_instance_count']
          if NewRelic::Security::Agent.config[:'security.iast_test_identifier'] && !NewRelic::Security::Agent.config[:'security.iast_test_identifier'].empty?
            headers[NR_CSEC_IAST_TEST_IDENTIFIER] = NewRelic::Security::Agent.config[:'security.iast_test_identifier']
            headers[NR_CSEC_IAST_SCAN_INSTANCE_COUNT] = 1
          end

          begin
            cert_store = ::OpenSSL::X509::Store.new
            cert_store.add_cert ::OpenSSL::X509::Certificate.new(::IO.read("#{__dir__}/../resources/cert.pem"))
            NewRelic::Security::Agent.logger.info "Websocket connection URL : #{NewRelic::Security::Agent.config[:validator_service_url]}"
            connection = NewRelic::Security::WebSocket::Client::Simple.connect NewRelic::Security::Agent.config[:validator_service_url], headers: headers, cert_store: cert_store
            @ws = connection
            @mutex = Mutex.new

            connection.on :open do
              headers = nil
              NewRelic::Security::Agent.logger.debug "Websocket connected with IC, AgentEventMachine #{NewRelic::Security::Agent::Utils.filtered_log(connection.inspect)}"
              NewRelic::Security::Agent.init_logger.info "[STEP-4] => Web socket connection to SaaS validator established successfully"
              NewRelic::Security::Agent.agent.event_processor.send_app_info
              NewRelic::Security::Agent.agent.event_processor.send_application_url_mappings
              NewRelic::Security::Agent.config.enable_security
              NewRelic::Security::Agent::Control::WebsocketClient.instance.start_ping_thread
            end
        
            connection.on :message do |msg|
              if msg.type == :ping
                connection.send(EMPTY_STRING, :type => :pong)
              elsif msg.type == :text
                # NewRelic::Security::Agent.logger.debug "Received IC Agent Message: #{msg.data.inspect}"
                ControlCommand.handle_ic_command(msg.data)
              end
            end

            connection.on :close do |e|
              NewRelic::Security::Agent.logger.info "Closing websocket connection : #{e.inspect}\n"
              NewRelic::Security::Agent.config.disable_security
              reconnect_interval = e.instance_of?(TrueClass) ? 0 : 15
              Thread.new { NewRelic::Security::Agent.agent.reconnect(reconnect_interval) } if e
            end

            connection.on :error do |e|
              NewRelic::Security::Agent.logger.error "Error in websocket connection : #{e.inspect} #{e.backtrace}"
              ::NewRelic::Agent.notice_error(e)
              Thread.new { NewRelic::Security::Agent::Control::WebsocketClient.instance.close(e) }
            end
          rescue Errno::EPIPE => exception
            NewRelic::Security::Agent.logger.error "Unable to connect to validator_service: #{exception.inspect}"
            ::NewRelic::Agent.notice_error(exception)
            NewRelic::Security::Agent.config.disable_security
          rescue Errno::ECONNRESET => exception
            NewRelic::Security::Agent.logger.error "Unable to connect to validator_service: #{exception.inspect}"
            ::NewRelic::Agent.notice_error(exception)
            NewRelic::Security::Agent.config.disable_security
            Thread.new { NewRelic::Security::Agent.agent.reconnect(15) }
          rescue Errno::ECONNREFUSED => exception
            NewRelic::Security::Agent.logger.error "Unable to connect to validator_service: #{exception.inspect}"
            ::NewRelic::Agent.notice_error(exception)
            NewRelic::Security::Agent.config.disable_security
            Thread.new { NewRelic::Security::Agent.agent.reconnect(15) }
          rescue => exception
            NewRelic::Security::Agent.logger.error "Exception in websocket init: #{exception.inspect} #{exception.backtrace}"
            ::NewRelic::Agent.notice_error(exception)
            NewRelic::Security::Agent.config.disable_security
            Thread.new { NewRelic::Security::Agent.agent.reconnect(15) }
          end
          headers = nil
        end

        def send(message)
          message_json = nil
          begin
            message_json = message.to_json
            NewRelic::Security::Agent.logger.debug "Sending #{message.jsonName} : #{message_json}"
            @mutex.synchronize do
              res = @ws.send(message_json)
              if res && message.jsonName == :Event
                NewRelic::Security::Agent.agent.event_sent_count.increment
                if NewRelic::Security::Agent::Utils.is_IAST_request?(message.httpRequest[:headers])
                  NewRelic::Security::Agent.agent.iast_event_stats.sent.increment
                else
                  NewRelic::Security::Agent.agent.rasp_event_stats.sent.increment
                end
              end
              NewRelic::Security::Agent.agent.exit_event_stats.sent.increment if res && message.jsonName == :'exit-event'
            end
          rescue Exception => exception
            NewRelic::Security::Agent.logger.error "Exception in sending message : #{exception.inspect} #{exception.backtrace}, message: #{message_json}"
            NewRelic::Security::Agent.agent.event_drop_count.increment if message.jsonName == :Event
            NewRelic::Security::Agent.agent.event_processor.send_critical_message(exception.message, "SEVERE", caller_locations[0].to_s, Thread.current.name, exception)
          ensure
            message_json = nil
          end
        end

        def close(reconnect = true)
          NewRelic::Security::Agent.config.disable_security
          NewRelic::Security::Agent.logger.info "Flushing eventQ (#{NewRelic::Security::Agent.agent.event_processor.eventQ.size} events) and closing websocket connection"
          NewRelic::Security::Agent.agent.event_processor&.eventQ&.clear
          @iast_client&.iast_data_transfer_request_processor_thread&.kill
          stop_ping_thread
          @ws.close(reconnect) if @ws
        end

        def is_open?
          return @ws.open? if @ws
          false
        end

        def start_ping_thread
          @ping_thread = Thread.new do
            loop do
              sleep 30
              @ws.send(EMPTY_STRING, :type => :ping)
            end
          end
        end

        private

        def stop_ping_thread
          @ping_thread&.kill
          @ping_thread = nil
        end

        def ingnored_vul_categories
          list = []
          list << FILE_OPERATION << FILE_INTEGRITY if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.invalid_file_access']
          list << SQL_DB_COMMAND if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.sql_injection']
          list << NOSQL_DB_COMMAND if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.nosql_injection']
          list << LDAP if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.ldap_injection']
          list << SYSTEM_COMMAND if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.command_injection']
          list << XPATH if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.xpath_injection']
          list << HTTP_REQUEST if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.ssrf']
          list << REFLECTED_XSS if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.rxss']
          list << RANDOM << SECURERANDOM if NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.insecure_settings']
          list
        end
      end
    end
  end
end
