# frozen_string_literal: true

require 'set'

module NewRelic::Security
  module Agent
    module Control
      
      HTTP_ = 'HTTP_'
      UNDERSCORE = '_'
      HYPHEN = '-'
      REQUEST_METHOD = 'REQUEST_METHOD'
      HTTP_HOST = 'HTTP_HOST'
      PATH_INFO = 'PATH_INFO'
      QUERY_STRING = 'QUERY_STRING'
      RACK_INPUT = 'rack.input'
      CGI_VARIABLES = ::Set.new(%W[ AUTH_TYPE CONTENT_LENGTH CONTENT_TYPE GATEWAY_INTERFACE HTTPS HTTP_HOST PATH_INFO PATH_TRANSLATED REQUEST_URI QUERY_STRING REMOTE_ADDR REMOTE_HOST REMOTE_IDENT REMOTE_USER REQUEST_METHOD SCRIPT_NAME SERVER_NAME SERVER_PORT SERVER_PROTOCOL SERVER_SOFTWARE rack.url_scheme ])
      REQUEST_BODY_LIMIT = 500 #KB

      class HTTPContext
        
        attr_accessor :time_stamp, :req, :method, :headers, :params, :body, :data_truncated, :route, :cache, :fuzz_files, :event_counter, :custom_data_type, :mutex, :url, :request_port

        def initialize(env)
          @time_stamp = current_time_millis
          @req = env.select { |key, _| CGI_VARIABLES.include? key}
          @method = @req[REQUEST_METHOD]
          @url = "#{@req[PATH_INFO]}?#{@req[QUERY_STRING]}"
          @headers = env.select { |key, _| key.include?(HTTP_) }
          @headers = @headers.transform_keys{ |key| key[5..-1].gsub(UNDERSCORE, HYPHEN).downcase }
          request = Rack::Request.new(env) unless env.empty?
          @request_port = NewRelic::Security::Agent::Utils.app_port(env)
					@params = request&.params
					@params&.each { |k, v| v.force_encoding(Encoding::UTF_8) if v.is_a?(String) }
          strio = env[RACK_INPUT]
          if strio.instance_of?(::StringIO)
						offset = strio.tell
						@body = strio.read(REQUEST_BODY_LIMIT * 1024) #after read, offset changes
						strio.seek(offset)
            # In case of Grape and Roda strio.read giving empty result, added below approach to handle such cases
            @body = strio.string if @body.nil? && strio.size > 0
          elsif defined?(::Rack) && defined?(::Rack::Lint::InputWrapper) && strio.instance_of?(::Rack::Lint::InputWrapper)
						@body = strio.read(REQUEST_BODY_LIMIT * 1024)
          elsif defined?(::Protocol::Rack::Input) && defined?(::Protocol::Rack::Input) && strio.instance_of?(::Protocol::Rack::Input)
            @body = strio.read(REQUEST_BODY_LIMIT * 1024)
          elsif defined?(::PhusionPassenger::Utils::TeeInput) && strio.instance_of?(::PhusionPassenger::Utils::TeeInput)
						@body = strio.read(REQUEST_BODY_LIMIT * 1024)
          end
          @data_truncated = @body && @body.size >= REQUEST_BODY_LIMIT * 1024
					strio&.rewind
					@body = @body.force_encoding(Encoding::UTF_8) if @body.is_a?(String)
          @custom_data_type = {}
          @cache = Hash.new
          @fuzz_files = ::Set.new
          @event_counter = 0
          @mutex = Mutex.new
          NewRelic::Security::Agent.agent.http_request_count.increment
          NewRelic::Security::Agent.agent.iast_client.completed_requests[@headers[NR_CSEC_PARENT_ID]] = [] if @headers.key?(NR_CSEC_PARENT_ID)
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def self.get_context
          ::NewRelic::Agent::Tracer.current_transaction.instance_variable_get(:@security_context_data) if ::NewRelic::Agent::Tracer.current_transaction.instance_variable_defined?(:@security_context_data)
        end

        def self.set_context(env)
          ::NewRelic::Agent::Tracer.current_transaction.instance_variable_set(:@security_context_data, HTTPContext.new(env))
        end

        def self.reset_context
          ::NewRelic::Agent::Tracer.current_transaction.remove_instance_variable(:@security_context_data) if ::NewRelic::Agent::Tracer.current_transaction.instance_variable_defined?(:@security_context_data)
        end

        def self.get_current_transaction
          ::NewRelic::Agent::Tracer.current_transaction
        end
      end

    end
  end
end