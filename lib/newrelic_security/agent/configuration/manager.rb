require 'securerandom'
require 'socket'
require 'openssl'
require 'newrelic_security/agent/configuration/default_source'
require 'newrelic_security/agent/configuration/environment_source'
require 'newrelic_security/agent/configuration/manual_source'
require 'newrelic_security/agent/configuration/server_source'
require 'newrelic_security/agent/configuration/yaml_source'

module NewRelic::Security
  module Agent
    module Configuration
      class Manager
        def initialize
          @cache = Hash.new
          @cache[:agent_run_id] = ::NewRelic::Agent.agent.service.agent_id
          @cache[:linking_metadata] = ::NewRelic::Agent.linking_metadata
          @cache[:app_name] = ::NewRelic::Agent.config[:app_name][0]
          @cache[:entity_guid] = ::NewRelic::Agent.config[:entity_guid]
          @cache[:license_key] = ::NewRelic::Agent.config[:license_key]
          @cache[:policy] = Hash.new
          @cache[:account_id] = nil
          @cache[:application_id] = nil
          @cache[:primary_application_id] = nil
          @cache[:log_file_path] = ::NewRelic::Agent.config[:log_file_path]
          @cache[:fuzz_dir_path] = ::File.join(::File.absolute_path(::NewRelic::Agent.config[:log_file_path]), SEC_HOME_PATH, TMP_DIR)
          @cache[:log_level] = ::NewRelic::Agent.config[:log_level]
          @cache[:high_security] = ::NewRelic::Agent.config[:high_security]
          @cache[:'agent.enabled'] = ::NewRelic::Agent.config[:'security.agent.enabled']
          @cache[:'security.enabled'] = ::NewRelic::Agent.config[:'security.enabled']
          @cache[:enabled] = false
          @cache[:mode] = ::NewRelic::Agent.config[:'security.mode']
          @cache[:validator_service_url] = ::NewRelic::Agent.config[:'security.validator_service_url']
          # TODO: Remove security.detection.* & security.request.body_limit in next major release
          @cache[:'security.detection.rci.enabled'] = ::NewRelic::Agent.config[:'security.detection.rci.enabled'].nil? ? true : ::NewRelic::Agent.config[:'security.detection.rci.enabled']
          @cache[:'security.detection.rxss.enabled'] = ::NewRelic::Agent.config[:'security.detection.rxss.enabled'].nil? ? true : ::NewRelic::Agent.config[:'security.detection.rxss.enabled']
          @cache[:'security.detection.deserialization.enabled'] = ::NewRelic::Agent.config[:'security.detection.deserialization.enabled'].nil? ? true : ::NewRelic::Agent.config[:'security.detection.deserialization.enabled']
          @cache[:'security.scan_controllers.iast_scan_request_rate_limit'] = ::NewRelic::Agent.config[:'security.scan_controllers.iast_scan_request_rate_limit'].to_i
          @cache[:framework] = detect_framework
          @cache[:app_class] = detect_app_class
          @cache[:'security.application_info.port'] = ::NewRelic::Agent.config[:'security.application_info.port'].to_i
          @cache[:listen_port] = nil
          @cache[:process_start_time] = current_time_millis # TODO: Ruby doesn't provide process start time in pure ruby implementation using agent loading time for now.
          @cache[:traffic_start_time] = nil
          @cache[:scan_start_time] = nil
          @cache[:'security.scan_controllers.scan_instance_count'] = ::NewRelic::Agent.config[:'security.scan_controllers.scan_instance_count']
          @cache[:'security.iast_test_identifier'] = ::NewRelic::Agent.config[:'security.iast_test_identifier']
          @cache[:app_root] = NewRelic::Security::Agent::Utils.app_root
          @cache[:jruby_objectspace_enabled] = false
          @cache[:json_version] = :'1.2.9'
          @cache[:'security.exclude_from_iast_scan.api'] = convert_to_regexp_list(::NewRelic::Agent.config[:'security.exclude_from_iast_scan.api'])
          @cache[:'security.exclude_from_iast_scan.http_request_parameters.header'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.http_request_parameters.header']
          @cache[:'security.exclude_from_iast_scan.http_request_parameters.query'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.http_request_parameters.query']
          @cache[:'security.exclude_from_iast_scan.http_request_parameters.body'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.http_request_parameters.body']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.insecure_settings'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.insecure_settings']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.invalid_file_access'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.invalid_file_access']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.sql_injection'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.sql_injection']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.nosql_injection'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.nosql_injection']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.ldap_injection'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.ldap_injection']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.javascript_injection'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.javascript_injection']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.command_injection'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.command_injection']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.xpath_injection'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.xpath_injection']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.ssrf'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.ssrf']
          @cache[:'security.exclude_from_iast_scan.iast_detection_category.rxss'] = ::NewRelic::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.rxss']
          @cache[:'security.scan_schedule.delay'] = ::NewRelic::Agent.config[:'security.scan_schedule.delay'].to_i
          @cache[:'security.scan_schedule.duration'] = ::NewRelic::Agent.config[:'security.scan_schedule.duration'].to_i
          @cache[:'security.scan_schedule.schedule'] = ::NewRelic::Agent.config[:'security.scan_schedule.schedule']
          @cache[:'security.scan_schedule.always_sample_traces'] = ::NewRelic::Agent.config[:'security.scan_schedule.always_sample_traces']

          @environment_source = NewRelic::Security::Agent::Configuration::EnvironmentSource.new
          @server_source = NewRelic::Security::Agent::Configuration::ServerSource.new
          @manual_source = NewRelic::Security::Agent::Configuration::ManualSource.new
          @yaml_source = NewRelic::Security::Agent::Configuration::YamlSource.new
          @default_source = NewRelic::Security::Agent::Configuration::DefaultSource.new
        rescue Exception => exception
          ::NewRelic::Agent.notice_error(exception)
        end
  
        def [](key)
          @cache[key]
        end
  
        def has_key?(key)
          @cache.has_key?(key)
        end
  
        def keys
          @cache.keys
        end

        def cache
          @cache
        end
    
        def refresh
          NewRelic::Security::Agent.logger.debug "refreshing agent config"
          NewRelic::Security::Agent.config = NewRelic::Security::Agent::Configuration::Manager.new
          # TODO: add validator received config also after the new, else collector#40 throws error
        end

        def save_uuid
          @cache[:uuid] = generate_uuid
        end

        def update_server_config
          @cache[:agent_run_id] = ::NewRelic::Agent.agent.service.agent_id
          @cache[:linking_metadata] = ::NewRelic::Agent.linking_metadata
          server_source = ::NewRelic::Agent.config.instance_variable_get(:@server_source) if defined?(::NewRelic::Agent)
          @cache[:account_id] = server_source[:account_id]
          @cache[:application_id] = server_source[:application_id]
          @cache[:entity_guid] = server_source[:entity_guid]
          @cache[:primary_application_id] = server_source[:primary_application_id]
          @cache[:extraction_key] = generate_key(@cache[:entity_guid])
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in update_server_config : #{exception.inspect} #{exception.backtrace}"
        end

        def update_port=(listen_port)
          @cache[:listen_port] = listen_port
        end

        def traffic_start_time=(traffic_start_time)
          @cache[:traffic_start_time] = traffic_start_time
        end

        def scan_start_time=(scan_start_time)
          @cache[:scan_start_time] = scan_start_time
        end

        def app_server=(app_server)
          @cache[:app_server] = app_server
        end

        def jruby_objectspace_enabled=(jruby_objectspace_enabled)
          @cache[:jruby_objectspace_enabled] = jruby_objectspace_enabled
        end

        def disable_security
          @cache[:enabled] = false
          NewRelic::Security::Agent.logger.info "Security Agent is now INACTIVE for #{NewRelic::Security::Agent.config[:uuid]}\n"
          NewRelic::Security::Agent.init_logger.info "Security Agent is now INACTIVE for #{NewRelic::Security::Agent.config[:uuid]}\n"
        end

        def enable_security
          @cache[:enabled] = true
          NewRelic::Security::Agent.logger.info "Security Agent is now ACTIVE for #{NewRelic::Security::Agent.config[:uuid]}\n"
          NewRelic::Security::Agent.init_logger.info "Security Agent is now ACTIVE for #{NewRelic::Security::Agent.config[:uuid]}\n"
          NewRelic::Security::Agent.agent.event_processor.send_critical_message("Security Agent is now ACTIVE for #{NewRelic::Security::Agent.config[:uuid]}", "INFO", caller_locations[0].to_s, Thread.current.name, nil)
        end

        private

        def detect_framework
          return :rails if defined?(::Rails)
          return :padrino if defined?(::Padrino)
          return :sinatra if defined?(::Sinatra)
          return :roda if defined?(::Roda)
          return :grape if defined?(::Grape)
          return :rack if defined?(::Rack) && defined?(Rack::Builder)
        end

        def detect_app_class
          target_class = nil
          ObjectSpace.each_object(::Rack::Builder) do |z| target_class = z.instance_variable_get(:@run).target end
          target_class
        rescue StandardError => exception
          NewRelic::Security::Agent.logger.error "Exception in detect_app_class : #{exception.inspect} #{exception.backtrace}"
          nil
        end

        def generate_uuid
          if defined?(::Puma::Cluster)
            ObjectSpace.each_object(::Puma::Cluster) { |z| return fetch_or_create_uuid if !z.preload? && z.instance_variable_get(:@options)[:workers] >= 1 }
          end
          if defined?(::Unicorn::HttpServer)
            ObjectSpace.each_object(::Unicorn::HttpServer) { |z| return fetch_or_create_uuid if !z.preload_app && z.worker_processes >= 1 }
          end
          if defined?(::PhusionPassenger::App) && ::PhusionPassenger::App.options[SPAWN_METHOD].match?(/#{DIRECT}/i)
            return create_uuid
          end
          ::SecureRandom.uuid
        rescue Exception => exception
          NewRelic::Security::Agent.logger.warn "Error in generate_uuid, generating it through default approach : #{exception.inspect} #{exception.backtrace}"
          ::SecureRandom.uuid
        end

        def create_uuid
          hostname = ::Socket.gethostname
          ip_addr = Socket.ip_address_list.detect{|intf| intf.ipv4_private?}.ip_address.to_s
          process_identity = ::Gem.win_platform? ? ::Process.pid : ::Process.getpgrp
          [hostname, ip_addr, process_identity].join(HYPHEN)
        end

        def fetch_or_create_uuid
          process_identity = ::Gem.win_platform? ? ::Process.pid : ::Process.getpgrp
          tmp_dir = ::File.join(@cache[:log_file_path], SEC_HOME_PATH, TMP_DIR)
          if ::File.directory?(tmp_dir)
            uuid_file_name = ::File.join(@cache[:log_file_path], SEC_HOME_PATH, TMP_DIR, process_identity.to_s)
          else
            ::FileUtils.mkdir_p(TMP_DIR) unless ::File.directory?(TMP_DIR)
            uuid_file_name = ::File.join(TMP_DIR, process_identity.to_s)
          end
          if ::File.exist?(uuid_file_name)
            sleep 0.01
            return ::File.read(uuid_file_name)
          end
          File.open(uuid_file_name, 'w', 0644) {|f|
            ret = f.flock(File::LOCK_EX|File::LOCK_NB)
            f.write(::SecureRandom.uuid) if ret == 0
          }
          ::File.read(uuid_file_name)
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in uuid file creation : #{exception.inspect} #{exception.backtrace}"
        end

        def generate_key(entity_guid)
          ::OpenSSL::PKCS5.pbkdf2_hmac(entity_guid, entity_guid[0..15], 1024, 32, SHA1)
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def convert_to_regexp_list(value_list)
          value_list.map do |value|
            next unless value && !value.empty?
            value = "^#{value}" if value[0] != '^'
            value = "#{value}$" if value[-1] != '$'
            /#{value}/
          end
        end
      end
    end
  end
end