# frozen_string_literal: true

require 'json'

module NewRelic::Security
  module Agent
    module Control

      class HTTPResponseEvent

        attr_accessor :isIASTRequest, :httpRequest, :httpResponse
        attr_reader :jsonName
        
        def initialize(ctxt, http_response)
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :sec_http_response
          @eventType = :sec_http_response
          @framework = NewRelic::Security::Agent.config[:framework]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @policyVersion = nil
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @appAccountId = NewRelic::Security::Agent.config[:account_id]
          @appEntityGuid = NewRelic::Security::Agent.config[:entity_guid]
          @httpRequest = {}
          @httpResponse = http_response.as_json
          @linkingMetadata = NewRelic::Security::Agent::Utils.add_linking_metadata
          @traceId = ctxt.trace_id
          @isIASTRequest = NewRelic::Security::Agent::Utils.is_IAST_request?(ctxt.headers)
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json # rubocop:disable Lint/ToJSON
          as_json.to_json
        end

      end
    end
  end
end