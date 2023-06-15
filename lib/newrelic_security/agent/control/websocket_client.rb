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
          
          begin
            cert_store = ::OpenSSL::X509::Store.new
            cert_store.add_cert ::OpenSSL::X509::Certificate.new(::IO.read("#{__dir__}/../resources/cert.pem"))
            NewRelic::Security::Agent.logger.info "Websocket connection URL : #{NewRelic::Security::Agent.config[:validator_service_url]}"
            connection = NewRelic::Security::WebSocket::Client::Simple.connect NewRelic::Security::Agent.config[:validator_service_url], headers: headers, cert_store: cert_store
            @ws = connection
          
            connection.on :open do
              NewRelic::Security::Agent.logger.debug "Websocket connected with IC, AgentEventMachine #{connection.inspect}"
              NewRelic::Security::Agent.init_logger.info "[STEP-4] => Web socket connection to SaaS validator established successfully"
              NewRelic::Security::Agent.agent.event_processor.send_app_info
              NewRelic::Security::Agent.config.enable_security
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
            end
            
            connection.on :error do |e|
              NewRelic::Security::Agent.logger.error "Error in websocket connection : #{e.inspect} #{e.backtrace}"
              NewRelic::Security::Agent.agent.reconnect(0)
            end
          rescue Errno::EPIPE => exception
            NewRelic::Security::Agent.logger.error "Unable to connect to validator_service: #{exception.inspect}"
            NewRelic::Security::Agent.config.disable_security
          rescue Errno::ECONNRESET => exception
            NewRelic::Security::Agent.logger.error "Unable to connect to validator_service: #{exception.inspect}"
            NewRelic::Security::Agent.config.disable_security
            NewRelic::Security::Agent.agent.reconnect(15)
          rescue Errno::ECONNREFUSED => exception
            NewRelic::Security::Agent.logger.error "Unable to connect to validator_service: #{exception.inspect}"
            NewRelic::Security::Agent.config.disable_security
            NewRelic::Security::Agent.agent.reconnect(15)
          rescue => exception
            NewRelic::Security::Agent.logger.error "Exception in websocket init: #{exception.inspect} #{exception.backtrace}"
            NewRelic::Security::Agent.config.disable_security
          end
          headers = nil
        end
      
        def send(message)
          message_json = message.to_json
          NewRelic::Security::Agent.logger.debug "Sending #{message.jsonName} : #{message_json}"
          res = @ws.send(message_json)
          NewRelic::Security::Agent.agent.event_sent_count.increment if res && message.jsonName == :Event
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in sending message : #{exception.inspect} #{exception.backtrace}"
          NewRelic::Security::Agent.agent.event_drop_count.increment if message.jsonName == :Event
        end

        def close
          @ws.close if @ws
        end

        def is_open?
          return @ws.open? if @ws
          false
        end
        
      end
    end
  end
end