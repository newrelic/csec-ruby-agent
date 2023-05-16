# Create Logger
module NewRelic::Security
    module Agent    
      module Control
        class HTTPContext
          def self.get_context
            # if you want to create event
            return false  
          end
        end
      end
      extend self
      def logger
        @logger ||= NewRelic::Security::Agent::Logging::AgentLogger.new
      end
  
      def init_logger
        @init_logger ||= NewRelic::Security::Agent::Logging::AgentInitLogger.new
      end

      def logger=(log)
        @logger = log
      end
      
      def config
        @config ||= NewRelic::Security::Agent::Configuration::Manager.new
      end
  
      def config=(new_config)
        @config = new_config
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
      rescue Exception => exception
        return false
      end
    end
  end