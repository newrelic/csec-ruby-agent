# frozen_string_literal: true

require 'json'
require 'digest'

module NewRelic::Security
  module Agent
    module Control
      class ApplicationRuntimeError
        attr_reader :jsonName, :exception
        attr_accessor :counter

        def initialize(exception, ctxt, response_code, category)
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :'application-runtime-error'
          @eventType = :'application-runtime-error'
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @timestamp = current_time_millis
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @appAccountId = NewRelic::Security::Agent.config[:account_id]
          @appEntityGuid = NewRelic::Security::Agent.config[:entity_guid]
          @framework = NewRelic::Security::Agent.config[:framework]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @policyVersion = nil
          @linkingMetadata = add_linking_metadata
          @httpRequest = get_http_request_data(ctxt)
          @exception = exception
          @counter = 1
          @responseCode = response_code
          @category = category
          @traceId = generate_trace_id(ctxt, category)
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json(*_args)
          as_json.to_json
        end

        private 

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def add_linking_metadata
          linking_metadata = {}
          linking_metadata[:agentRunId] = NewRelic::Security::Agent.config[:agent_run_id]
          linking_metadata.merge!(NewRelic::Security::Agent.config[:linking_metadata])
          # TODO: add other fields as well in linking metadata, for event and heathcheck as well
        end

        def get_http_request_data(ctxt)
          return if ctxt.nil?
          http_request = {}
          http_request[:parameterMap] = {}
          http_request[:body] = ctxt.body
          http_request[:generationTime] = ctxt.time_stamp
          http_request[:dataTruncated] = false
          http_request[:method] = ctxt.method
          http_request[:route] = ctxt.route.split(AT_THE_RATE)[1] if ctxt.route
          http_request[:url] = URI(ctxt.req[REQUEST_URI]).respond_to?(:request_uri) ? URI(ctxt.req[REQUEST_URI]).request_uri : ctxt.req[REQUEST_URI]
          http_request[:requestURI] = "#{ctxt.req[RACK_URL_SCHEME]}://#{ctxt.req[HTTP_HOST]}#{ctxt.req[PATH_INFO]}"
          http_request[:clientIP] = ctxt.headers.key?(X_FORWARDED_FOR) ? ctxt.headers[X_FORWARDED_FOR].split(COMMA)[0].to_s : ctxt.req[REMOTE_ADDR].to_s
          http_request[:serverPort] = ctxt.req[SERVER_PORT].to_i
          http_request[:protocol] = ctxt.req[RACK_URL_SCHEME]
          http_request[:contextPath] = ROOT_PATH
          http_request[:headers] = ctxt.headers
          http_request[:contentType] = ctxt.req[CONTENT_TYPE] if ctxt.req.key?(CONTENT_TYPE)
          http_request[:headers][CONTENT_TYPE1] = ctxt.req[CONTENT_TYPE] if ctxt.req.key?(CONTENT_TYPE)
          http_request[:dataTruncated] = ctxt.data_truncated
          http_request
        end

        def generate_trace_id(ctxt, category)
          @exception[:stackTrace]
          method, route = ctxt.route.split(AT_THE_RATE) if ctxt&.route
          if @exception[:stackTrace]
            ::Digest::SHA256.hexdigest("#{@exception[:stackTrace].join(PIPE)}#{category}#{route}#{method}").to_s
          else
            ::Digest::SHA256.hexdigest("#{category}#{route}#{method}").to_s
          end
        end

      end
    end
  end
end