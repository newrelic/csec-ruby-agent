# Create Config
module NewRelic::Security
  module Agent
    module Configuration
      class Manager
        def initialize
          @cache = Hash.new
          @cache[:log_level] = ENV['NR_CSEC_LOG_LEVEL']
          @cache[:log_file_path] = "log"
          @cache[:framework] = ""
          @cache[:groupName] = ""
          @cache[:uuid] = ""
          @cache[:listen_port] = ""
          @cache[:agent_run_id] = ""
          @cache[:linking_metadata] = {}
          @cache[:app_root] = File.expand_path('../../resources/temp', __FILE__)
          @cache[:policy] = Hash.new
          @cache[:'security.detection.rxss.enabled'] = true
          @cache[:'security.request.body_limit'] = 300
        end
      end
    end
  end
end