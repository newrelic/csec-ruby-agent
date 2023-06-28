require 'json'

module NewRelic::Security
  module Agent
    module Control
      class Health
        attr_reader :jsonName, :stats, :serviceStatus

        def initialize
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :LAhealthcheck
          @eventType = :sec_health_check_lc
          @timestamp = current_time_millis
          @version = EMPTY_STRING
          @groupName = NewRelic::Security::Agent.config[:mode]
          @policyVersion = nil
          @framework = NewRelic::Security::Agent.config[:framework]
          @protectedServer = nil
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @eventSentCount = 0
          @eventProcessed = 0
          @eventDropCount = 0
          @httpRequestCount = 0
          @protectedVulnerabilties = nil
          @protectedDB = nil
          @linkingMetadata = add_linking_metadata
          @stats = {}
          @serviceStatus = {} # TODO: Fill this
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json
          as_json.to_json
        end

        def update_health_check
          @httpRequestCount = NewRelic::Security::Agent.agent.http_request_count.fetch_and_reset_counter
          @eventProcessed = NewRelic::Security::Agent.agent.event_processed_count.fetch_and_reset_counter
          @eventSentCount = NewRelic::Security::Agent.agent.event_sent_count.fetch_and_reset_counter
          @eventDropCount = NewRelic::Security::Agent.agent.event_drop_count.fetch_and_reset_counter
          @stats[:nCores] = nil # TODO: add cpu count here
          @stats[:systemTotalMemoryMB] = system_total_memory_mb
          @stats[:systemFreeMemoryMB] = system_free_memory_mb
          @stats[:systemCpuLoad] = system_cpu_load
          @stats[:processCpuUsage] = nil
          @stats[:processRssMB] = nil # TODO: add process rss here
          @stats[:processMaxHeapMB] = nil
          @stats[:processHeapUsageMB] = nil
          @stats[:processDirDiskFreeSpaceMB] = nil
          @stats[:rootDiskFreeSpaceMB] = nil
          @serviceStatus[:websocket] = NewRelic::Security::Agent::Control::WebsocketClient.instance.is_open? ? 'OK' : 'Error'
          @serviceStatus[:logWriter] = NewRelic::Security::Agent.logger ? 'OK' : 'Error'
          @serviceStatus[:initLogWriter] = NewRelic::Security::Agent.init_logger ? 'OK' : 'Error'
          @serviceStatus[:statusLogWriter] = NewRelic::Security::Agent.agent.status_logger ? 'OK' : 'Error'
          @serviceStatus[:agentActiveStat] = NewRelic::Security::Agent.config[:enabled] ? 'OK' : 'Error'
          @serviceStatus[:iastRestClient] = NewRelic::Security::Agent::Utils.is_IAST? && !NewRelic::Security::Agent.agent.iast_client ? 'Error' : 'OK'
        rescue Exception => exception
          NewRelic::Security::Agent::logger.error "Exception in finding update_health_check : #{exception.inspect} #{exception.backtrace}"
        end

        private
        
        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def add_linking_metadata
          linking_metadata = Hash.new
          linking_metadata[:agentRunId] = NewRelic::Security::Agent.config[:agent_run_id]
          linking_metadata.merge!(NewRelic::Security::Agent.config[:linking_metadata])
        end

        def system_total_memory_mb
          case RbConfig::CONFIG['host_os']
          when /darwin9/
            `sysctl -n hw.memsize`.to_f/1024**2
          when /darwin/
            `sysctl -n hw.memsize`.to_f/1024**2
          when /linux/
            `awk '/MemTotal/ {print $2}' /proc/meminfo`.to_f/1024
          when /freebsd/
            `sysctl sysctl hw.physmem`.to_f/1024**2
          end
        rescue Exception => exception
          NewRelic::Security::Agent::logger.error "Exception in finding system_total_memory_mb : #{exception.inspect} #{exception.backtrace}"
        end
    
        def system_free_memory_mb
          # TODO: Add free memory logic for darwin
          case RbConfig::CONFIG['host_os']
          when /darwin9/
            ''
          when /darwin/
            ''
          when /linux/
            `awk '/MemFree/ {print $2}' /proc/meminfo`.to_f/1024
          when /freebsd/
            ''
          end
        rescue Exception => exception
          NewRelic::Security::Agent::logger.error "Exception in finding system_free_memory_mb : #{exception.inspect} #{exception.backtrace}"
        end
    
        def system_cpu_load
          case RbConfig::CONFIG['host_os']
          when /darwin9/
            `uptime | awk '// {print $11}'`.to_f
          when /darwin/
            `uptime | awk '// {print $11}'`.to_f
          when /linux/
            `uptime | awk '// {print $11}' | sed 's/,$//'`.to_f
          when /freebsd/
            ''
          end
        rescue Exception => exception
          NewRelic::Security::Agent::logger.error "Exception in finding system_cpu_load : #{exception.inspect} #{exception.backtrace}"
        end

      end 
    end
  end
end