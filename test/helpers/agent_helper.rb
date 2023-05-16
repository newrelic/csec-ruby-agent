# Agent helper
module NewRelic::Security
  module Agent    
    module Control
      class HTTPContext
        def self.get_context
          # if you want to create complete event, return true
          return @http_context if @http_context
        end
        def self.set_context(env)
          @http_context = HTTPContext.new(env)
        end

        def self.reset_context
          # @http_context = nil
        end
      end
    end
    
    extend self

    def agent()
      return @agent if @agent
      puts "Agent unavailable as it hasn't been started."
      nil
    end
    
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
      log_dir = ::File.join(DEFAULT_SEC_HOME_PATH, LOGS_DIR)
      find_or_create_file_path(log_dir)
      tmp_dir = ::File.join(DEFAULT_SEC_HOME_PATH, TMP_DIR)
      find_or_create_file_path(tmp_dir)
    end
    
    def find_or_create_file_path(path)
      ::FileUtils.mkdir_p(path) unless ::File.directory?(path)
      ::File.directory?(path)
    rescue
      return false
    end

  end
end