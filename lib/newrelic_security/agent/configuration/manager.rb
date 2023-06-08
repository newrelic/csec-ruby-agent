require 'securerandom'
require 'socket'
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
          @cache[:log_file_path] = ::File.absolute_path(::NewRelic::Agent.config[:log_file_path])
          @cache[:log_level] = ::NewRelic::Agent.config[:log_level]
          @cache[:high_security] = ::NewRelic::Agent.config[:high_security]
          @cache[:'agent.enabled'] = ::NewRelic::Agent.config[:'security.agent.enabled']
          @cache[:enabled] = ::NewRelic::Agent.config[:'security.enabled']
          @cache[:mode] = ::NewRelic::Agent.config[:'security.mode']
          @cache[:validator_service_url] = ::NewRelic::Agent.config[:'security.validator_service_url']
          @cache[:'security.detection.rci.enabled'] = ::NewRelic::Agent.config[:'security.detection.rci.enabled']
          @cache[:'security.detection.rxss.enabled'] = ::NewRelic::Agent.config[:'security.detection.rxss.enabled']
          @cache[:'security.detection.deserialization.enabled'] = ::NewRelic::Agent.config[:'security.detection.deserialization.enabled']
          @cache[:framework] = detect_framework
          @cache[:'security.application_info.port'] = ::NewRelic::Agent.config[:'security.application_info.port'].to_i
          @cache[:listen_port] = nil
          @cache[:app_root] = NewRelic::Security::Agent::Utils.app_root
          @cache[:json_version] = :'1.0.1'

          @environment_source = NewRelic::Security::Agent::Configuration::EnvironmentSource.new
          @server_source = NewRelic::Security::Agent::Configuration::ServerSource.new
          @manual_source = NewRelic::Security::Agent::Configuration::ManualSource.new
          @yaml_source = NewRelic::Security::Agent::Configuration::YamlSource.new
          @default_source = NewRelic::Security::Agent::Configuration::DefaultSource.new
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
        end

        def update_port=(listen_port)
          @cache[:listen_port] = listen_port
        end

        def app_server=(app_server)
          @cache[:app_server] = app_server
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
        end

        private

        def detect_framework
          return :rails if defined?(::Rails)
          return :sinatra if defined?(::Sinatra)
        end

        def generate_uuid
          if defined?(::Puma::Cluster)
            ObjectSpace.each_object(::Puma::Cluster) { |z| return fetch_or_create_uuid if !z.preload? && z.instance_variable_get(:@options)[:workers] > 1 }
          end
          if defined?(::Unicorn::HttpServer)
            ObjectSpace.each_object(::Unicorn::HttpServer) { |z| return fetch_or_create_uuid if !z.preload_app && z.worker_processes > 1 }
          end
          if defined?(::PhusionPassenger::App) && ::PhusionPassenger::App.options[SPAWN_METHOD].match?(/#{DIRECT}/i)
            return create_uuid
          end
          ::SecureRandom.uuid
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in generate_uuid : #{exception.inspect} #{exception.backtrace}"
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
      end
    end
  end
end