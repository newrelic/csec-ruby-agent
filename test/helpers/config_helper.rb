# Create Config
module NewRelic::Security
  module Agent
    module Configuration
      class Manager
        def initialize
          @cache = Hash.new
          @cache[:log_level] = ENV['NR_CSEC_LOG_LEVEL']
          @cache[:framework] = ""
          @cache[:groupName] = ""
          @cache[:uuid] = ""
          @cache[:listen_port] = ""
          @cache[:agent_run_id] = ""
          @cache[:linking_metadata] = {}
          @cache[:app_root] = File.expand_path('../../lib', __FILE__)
          @cache[:policy] = Hash.new
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
      end
    end
  end
end