# frozen_string_literal: true

require 'json'

module NewRelic::Security
  module Agent
    module Control

      class CriticalMessage

        attr_reader :jsonName
        
        def initialize(message, level, caller, thread_name, exception = nil)
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :'critical-messages'
          @framework = NewRelic::Security::Agent.config[:framework]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @policyVersion = nil
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @appAccountId = NewRelic::Security::Agent.config[:account_id]
          @appEntityGuid = NewRelic::Security::Agent.config[:entity_guid]
          @linkingMetadata = add_linking_metadata
          @timestamp = current_time_millis
          @message = message
          @level = level          
          @caller = caller
          @threadName = thread_name
          @exception = exception
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json
          as_json.to_json
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

      end
    end
  end
end