# frozen_string_literal: true

require 'json'
require 'uri'

module NewRelic::Security
  module Agent
    module Control

      ROOT_PATH = '/'

      class Event

        attr_accessor :sourceMethod, :userMethodName, :userFileName, :lineNumber,  :id, :apiId, :isIASTEnable, :isIASTRequest, :httpRequest, :httpResponse, :stacktrace, :metaData, :parentId
        attr_reader :jsonName, :caseType, :eventCategory, :parameters
        
        def initialize(case_type, args, event_category)
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :Event
          @eventType = :sec_event
          @framework = NewRelic::Security::Agent.config[:framework]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @policyVersion = nil
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @appAccountId = NewRelic::Security::Agent.config[:account_id]
          @appEntityGuid = NewRelic::Security::Agent.config[:entity_guid]
          @httpRequest = Hash.new
          @httpResponse = Hash.new
          @metaData = { :reflectedMetaData => { :listen_port => NewRelic::Security::Agent.config[:listen_port].to_s } }
          @linkingMetadata = add_linking_metadata
          @pid = pid
          @parameters = args
          @sourceMethod = nil
          @userMethodName = nil
          @userFileName = nil
          @lineNumber = nil
          @caseType = case_type
          @eventCategory = event_category
          @id = event_id
          @eventGenerationTime = current_time_millis
          @startTime = current_time_millis
          @stacktrace = []
          @apiId = nil
          @isAPIBlocked = nil
          @isIASTEnable = false
          @isIASTRequest = false
          @parentId = nil
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json
          as_json.to_json
        end

        # # TODO: Use this approach if, performace is very low with require 'json'
        # def as_json(options={})
        #   {
        #       fname: @fname,
        #       lname: @lname
        #   }
        # end
        
        # # This method needs, require 'json'
        # def to_json(*options)
        #     as_json(*options).to_json(*options)
        # end

        def copy_http_info(ctxt)
          return if ctxt.nil?
          http_request = {}
          http_request[:parameterMap] = {}
          http_request[:body] = ctxt.body
          http_request[:generationTime] = ctxt.time_stamp
          http_request[:dataTruncated] = false
          http_request[:method] = ctxt.method
          http_request[:route] = ctxt.route.split(AT_THE_RATE)[1] if ctxt.route
          http_request[:url] = URI(ctxt.req[REQUEST_URI]).respond_to?(:request_uri) ? URI(ctxt.req[REQUEST_URI]).request_uri : ctxt.req[REQUEST_URI]
          http_request[:clientIP] = ctxt.headers.has_key?(X_FORWARDED_FOR) ? ctxt.headers[X_FORWARDED_FOR].split(COMMA)[0].to_s : ctxt.req[REMOTE_ADDR].to_s
          http_request[:serverPort] = ctxt.req[SERVER_PORT].to_i
          http_request[:protocol] = ctxt.req[RACK_URL_SCHEME]
          http_request[:contextPath] = ROOT_PATH
          http_request[:headers] = ctxt.headers
          http_request[:contentType] = ctxt.req[CONTENT_TYPE] if ctxt.req.has_key?(CONTENT_TYPE)
          http_request[:headers][CONTENT_TYPE1] = ctxt.req[CONTENT_TYPE] if ctxt.req.has_key?(CONTENT_TYPE)
          http_request[:dataTruncated] = ctxt.data_truncated
          @httpRequest = http_request
          @metaData[:isClientDetectedFromXFF] = ctxt.headers.has_key?(X_FORWARDED_FOR) ? true : false
        end

        def copy_grpc_info(ctxt)
          # TODO: optimise this method and combine copy_http_info and copy_grpc_info
          return if ctxt.nil?
          http_request = {}
          http_request[:body] = ctxt.body.is_a?(Array) ? "[#{ctxt.body.join(',')}]" : ctxt.body
          http_request[:generationTime] = ctxt.time_stamp
          http_request[:dataTruncated] = false
          http_request[:method] = ctxt.method
          http_request[:route] = ctxt.route
          http_request[:url] = ctxt.url
          http_request[:serverName] = ctxt.server_name
          http_request[:serverPort] = ctxt.server_port
          http_request[:clientIP] = ctxt.client_ip
          http_request[:clientPort] = ctxt.client_port
          http_request[:protocol] = :grpc
          http_request[:headers] = ctxt.headers
          http_request[:contentType] = "TODO: "
          http_request[:isGrpc] = ctxt.is_grpc
          @httpRequest = http_request
          @metaData = ctxt.metadata
        end

        private

        def pid
          return ::Process.pid if ::Gem.win_platform?
          ::Process.getpgrp
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def event_id
          "#{Process.pid}:#{current_transaction.guid}:#{thread_monotonic_ctr}"
        end

        def current_transaction
          ::NewRelic::Agent::Tracer.current_transaction
        end

        def thread_monotonic_ctr
          ctxt = NewRelic::Security::Agent::Control::HTTPContext.get_context if NewRelic::Security::Agent::Control::HTTPContext.get_context
          ctxt = NewRelic::Security::Agent::Control::GRPCContext.get_context if NewRelic::Security::Agent::Control::GRPCContext.get_context
          return unless ctxt
          ctxt.mutex.synchronize do
            ctxt.event_counter = ctxt.event_counter + 1
          end
        end

        def add_linking_metadata
          linking_metadata = Hash.new
          linking_metadata[:agentRunId] = NewRelic::Security::Agent.config[:agent_run_id]
          linking_metadata.merge!(NewRelic::Security::Agent.config[:linking_metadata])
        end

      end
    end
  end
end