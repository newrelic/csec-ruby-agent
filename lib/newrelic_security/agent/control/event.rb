# frozen_string_literal: true

require 'json'
require 'uri'

module NewRelic::Security
  module Agent
    module Control

      ROOT_PATH = '/'

      class Event

        attr_accessor :sourceMethod, :userMethodName, :userFileName, :lineNumber,  :id, :apiId, :isIASTEnable, :isIASTRequest, :httpRequest, :stacktrace, :metaData
        attr_reader :jsonName, :caseType, :eventCategory, :parameters
        
        def initialize(case_type, args, event_category)
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :Event
          @eventType = :sec_event
          @framework = NewRelic::Security::Agent.config[:framework]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @nodeId = nil
          @customerId = nil
          @emailId = nil
          @policyVersion = nil
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @httpRequest = Hash.new
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
          http_request[:url] = URI(ctxt.req[REQUEST_URI]).respond_to?(:request_uri) ? URI(ctxt.req[REQUEST_URI]).request_uri : ctxt.req[REQUEST_URI]
          http_request[:clientIP] = ctxt.headers.has_key?(X_FORWARDED_FOR) ? ctxt.headers[X_FORWARDED_FOR].split(COMMA)[0].to_s : ctxt.req[REMOTE_ADDR].to_s
          http_request[:serverPort] = ctxt.req[SERVER_PORT].to_i
          http_request[:protocol] = ctxt.req[RACK_URL_SCHEME]
          http_request[:contextPath] = ROOT_PATH
          http_request[:headers] = ctxt.headers
          http_request[:contentType] = ctxt.req[CONTENT_TYPE] if ctxt.req.has_key?(CONTENT_TYPE)
          http_request[:headers][CONTENT_TYPE1] = ctxt.req[CONTENT_TYPE] if ctxt.req.has_key?(CONTENT_TYPE)
          @httpRequest = http_request
          @metaData[:isClientDetectedFromXFF] = ctxt.headers.has_key?(X_FORWARDED_FOR) ? true : false
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
          "#{Process.pid}:#{::Thread.current.object_id}:#{thread_monotonic_ctr}"
        end

        def thread_monotonic_ctr
          ::Thread.current[:kevent_ctr] = 0 if ::Thread.current[:kevent_ctr].nil?
          ::Thread.current[:kevent_ctr] = ::Thread.current[:kevent_ctr] + 1
          ::Thread.current[:kevent_ctr]
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