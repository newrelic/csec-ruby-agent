require 'newrelic_security/agent/control/event_subscriber'
require 'newrelic_security/agent/control/websocket_client'
require 'newrelic_security/agent/control/event_processor'
require 'newrelic_security/agent/control/iast_client'
require 'newrelic_security/agent/control/iast_data_transfer_request'
require 'newrelic_security/agent/control/control_command'
require 'newrelic_security/agent/control/fuzz_request'
require 'newrelic_security/agent/control/reflected_xss'
require 'newrelic_security/agent/control/http_context'
require 'newrelic_security/agent/control/grpc_context'
require 'newrelic_security/agent/control/collector'
require 'newrelic_security/agent/control/app_info'
require 'newrelic_security/agent/control/application_url_mappings'
require 'newrelic_security/agent/control/health_check'
require 'newrelic_security/agent/control/event'
require 'newrelic_security/agent/control/critical_message'
require 'newrelic_security/agent/control/event_counter'
require 'newrelic_security/agent/control/event_stats'
require 'newrelic_security/agent/control/exit_event'
require 'newrelic_security/agent/control/application_runtime_error'
require 'newrelic_security/agent/control/error_reporting'
require 'newrelic_security/agent/control/scan_scheduler'
require 'newrelic_security/instrumentation-security/instrumentation_loader'

module NewRelic::Security
  module Agent
    class Agent

      attr_accessor :websocket_client, :event_processor, :iast_client, :http_request_count, :event_processed_count, :event_sent_count, :event_drop_count, :route_map, :iast_event_stats, :rasp_event_stats, :exit_event_stats, :error_reporting, :scan_scheduler

      def initialize
        NewRelic::Security::Agent.config
        create_agent_home
        NewRelic::Security::Agent::Utils.enable_object_space_in_jruby
        NewRelic::Security::Agent.config.save_uuid
        @started = false
        @event_subscriber = NewRelic::Security::Agent::Control::EventSubscriber.new
        @started = true
        @route_map = ::Set.new
        @http_request_count = NewRelic::Security::Agent::Control::EventCounter.new
        @event_processed_count = NewRelic::Security::Agent::Control::EventCounter.new
        @event_sent_count = NewRelic::Security::Agent::Control::EventCounter.new
        @event_drop_count = NewRelic::Security::Agent::Control::EventCounter.new
        @iast_event_stats = NewRelic::Security::Agent::Control::EventStats.new
        @rasp_event_stats = NewRelic::Security::Agent::Control::EventStats.new
        @exit_event_stats = NewRelic::Security::Agent::Control::EventStats.new
        @error_reporting = NewRelic::Security::Agent::Control::ErrorReporting.new
        @scan_scheduler = NewRelic::Security::Agent::Control::ScanScheduler.new
      end

      def init
        NewRelic::Security::Agent.logger.info "Initializing Security Agent with config : #{NewRelic::Security::Agent::Utils.filtered_log(NewRelic::Security::Agent.config.inspect)}\n"
        @ready = false
        start_event_processor
        start_websocket_client
        NewRelic::Security::Instrumentation::InstrumentationLoader.add_instrumentation()
        NewRelic::Security::Agent.logger.info "Security Agent ready.\n"
        NewRelic::Security::Agent.init_logger.info "Security Agent ready.\n"
        @ready = true
      rescue Exception => exception
        NewRelic::Security::Agent.logger.error "Exception in security agent init: #{exception.inspect} #{exception.backtrace}\n"
      end

      def start_websocket_client
        stop_websocket_client_if_open
        @websocket_client = NewRelic::Security::Agent::Control::WebsocketClient.instance.connect
      end

      def stop_websocket_client_if_open
        NewRelic::Security::Agent::Control::WebsocketClient.instance.close(false) if NewRelic::Security::Agent::Control::WebsocketClient.instance.is_open?
      end

      def start_event_processor
        @event_processor&.event_dequeue_thread&.kill 
        @event_processor&.healthcheck_thread&.kill
        @event_processor = nil
        @event_processor = NewRelic::Security::Agent::Control::EventProcessor.new
      end

      def start_iast_client
        @iast_client&.iast_dequeue_threads&.each { |t| t.kill if t }
        @iast_client&.iast_data_transfer_request_processor_thread&.kill
        @iast_client = nil
        @iast_client = NewRelic::Security::Agent::Control::IASTClient.new
      end

      def self.config
        ::NewRelic::Security::Agent.config
      end

      def add_instrumentation
        
      end

      def create_agent_home
        log_dir = ::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, LOGS_DIR)
        find_or_create_file_path(log_dir)
        tmp_dir = ::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, TMP_DIR)
        find_or_create_file_path(tmp_dir)
      end

      def find_or_create_file_path(path)
        ::FileUtils.mkdir_p(path) unless ::File.directory?(path)
        ::File.directory?(path)
      rescue => e
        ::NewRelic::Agent.notice_error(e)
        return false
      end

      def reconnect(sleep_time = 15)
        NewRelic::Security::Agent::Control::WebsocketClient.instance.close(false) if NewRelic::Security::Agent::Control::WebsocketClient.instance.is_open?
        NewRelic::Security::Agent.logger.info "Trying to reconnect to websocket connection in #{sleep_time} sec..."
        sleep sleep_time
        NewRelic::Security::Agent.agent.start_websocket_client
      end

    end
  end
end