# frozen_string_literal: true
require 'logger'

module NewRelic::Security
  module Agent
    module Logging
      LOG_FILE_NAME = 'ruby-security-collector.log'

      class AgentLogger
        def initialize
          create_log_to_file
        end
  
        def fatal(msg)
          @logger.fatal(msg)
        end
  
        def error(msg)
          @logger.error(msg)
        end
  
        def warn(msg)
          @logger.warn(msg)
        end
  
        def info(msg)
          @logger.info(msg)
        end
  
        def debug(msg)
          @logger.debug(msg)
        end
  
        private

        def prepped_logger(target)
          @logger = ::Logger.new(target)
          @logger.level = AgentLogger.log_level_for(NewRelic::Security::Agent.config[:log_level])
          @logger.instance_variable_set(:@skip_instrumenting, true)
          @logger.freeze
          @logger
        end
  
        LOG_LEVELS = {
          "debug" => ::Logger::DEBUG,
          "info" => ::Logger::INFO,
          "warn" => ::Logger::WARN,
          "error" => ::Logger::ERROR,
          "fatal" => ::Logger::FATAL
        }
  
        def self.log_level_for(level)
          LOG_LEVELS.fetch(level.to_s.downcase, ::Logger::INFO)
        end

        def create_log_to_file
          log_dir = ::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, LOGS_DIR)
          path = ::File.directory?(log_dir)
          if path
            file_path = "#{log_dir}/#{LOG_FILE_NAME}"
            begin
              @logger = prepped_logger(file_path)
            rescue => e
              @logger = prepped_logger(STDOUT)
              warn("Failed creating logger for file #{file_path}, using standard out for logging. #{e}")
            end
          else
            @logger = prepped_logger(STDOUT)
            warn("Error creating log directory #{::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, LOGS_DIR)}, using standard out for logging.")  
          end
        end

      end
    end
  end
end
