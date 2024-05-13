module NewRelic::Security
  module Agent
    module Logging
      
      LAST_ERRORS_SIZE = 5
      LAST_HEALTHCHECKS_SIZE = 5
      PROC_SELF_EXE = '/proc/self/exe'

      class StatusLogger
        def initialize
          @last_errors = Array.new
          @last_healthchecks = Array.new
          @agent_start_timestamp = Time.now
          @status = true
        end

        def add_error_in_last_errors(error)
          if @last_errors.size == LAST_ERRORS_SIZE
            @last_errors.shift
          end
          @last_errors.push(error)
        end
  
        def add_healthcheck_in_last_healthchecks(healthcheck)
          if @last_healthchecks.size == LAST_HEALTHCHECKS_SIZE
            @last_healthchecks.shift
          end
          @last_healthchecks.push(healthcheck)
        end

        def create_snapshot()
          begin
            status_template = String.new
            status_template << "Snapshot timestamp: #{Time.now}"
            status_template << "\nCSEC Ruby Agent start timestamp: #{@agent_start_timestamp} with application uuid: #{NewRelic::Security::Agent.config[:uuid]}"
            status_template << "\nCSEC HOME: #{::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH)})"
            status_template << "\nAgent location: "
            status_template << "\nUsing CSEC for Ruby, Ruby version: #{RUBY_VERSION}, PID: #{Process.pid}"
            status_template << "\nProcess title: ruby"
            status_template << "\nProcess binary: #{binary_path}"
            status_template << "\nApplication location: #{NewRelic::Security::Agent.config[:app_root]}"
            status_template << "\nCurrent working directory: #{NewRelic::Security::Agent.config[:app_root]}"
            status_template << "\nAgent mode: #{NewRelic::Security::Agent.config[:mode]}"
            status_template << "\nApplication server: #{NewRelic::Security::Agent.config[:app_server]}"
            status_template << "\nApplication Framework: #{NewRelic::Security::Agent.config[:framework]}"
            status_template << "\nWebsocket connection to Prevent Web: #{NewRelic::Security::Agent.config[:validator_service_url]}, Status: #{NewRelic::Security::Agent::Control::WebsocketClient.instance.is_open? ? 'OK' : 'Error'}"
            status_template << "\nInstrumentation successful:"
            status_template << "\nTracking loaded modules in the application:"
            status_template << "\nPolicy applied successfully. Policy version is: #{NewRelic::Security::Agent.config[:policy]['version']}"
            status_template << "\nStarted Health Check for Agent"
            status_template << "\nStarted Inbound and Outbound monitoring"
    
            status_template << "\nProcess stats:\n"
            @last_healthchecks.last.stats.each {
              |key, value| 
              status_template << "#{key}: #{value}\n"
            } unless @last_healthchecks.last.nil?
            status_template << "\nService stats:\n"
            @last_healthchecks.last.serviceStatus.each {
              |key, value| 
              status_template << "#{key}: #{value}\n"
            } unless @last_healthchecks.last.nil?
            
            status_template << "\nLast 5 errors: \n["
            @last_errors.each {
              |x| status_template << x.to_json + ','
            }
            status_template << "]"
    
            status_template << "\nLast 5 Health Checks are: \n["
            @last_healthchecks.each {
              |x| status_template << x.to_json + ','
            }
            status_template << "]" 
            write_status_log_in_file(status_template)  
            @status = true
          rescue => exception
            NewRelic::Security::Agent.logger.error "Exception in status snapshot creation : #{exception} #{exception.backtrace}"
            @status = false
          end
        end

        private

        def write_status_log_in_file(data)
          FileUtils.mkdir_p(::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, LOGS_DIR, SNAPSHOTS_DIR)) unless File.directory?(::File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, LOGS_DIR, SNAPSHOTS_DIR))
          filename = File.join(NewRelic::Security::Agent.config[:log_file_path], SEC_HOME_PATH, LOGS_DIR, SNAPSHOTS_DIR, "ruby-security-collector-status-#{NewRelic::Security::Agent.config[:uuid]}.log")
          File.open(filename, 'w') {
            |file| file.write(data)
          }
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in status snapshot writing to file : #{exception} #{exception.backtrace}"
          @status = false
        end
        
        def binary_path
          return ::File.realpath(PROC_SELF_EXE) if ::File.exist?(PROC_SELF_EXE)
          nil
        end

      end
    end
  end
end