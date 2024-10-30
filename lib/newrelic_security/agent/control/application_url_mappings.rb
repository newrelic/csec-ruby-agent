# frozen_string_literal: true

require 'set'
require 'json'

module NewRelic::Security
  module Agent
    module Control
      

      class ApplicationURLMappings
        attr_reader :jsonName

        def initialize
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :'sec-application-url-mapping'
          @eventType = :'sec-application-url-mapping'
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
          @linkingMetadata = NewRelic::Security::Agent::Utils.add_linking_metadata
          @mappings = []
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json # rubocop:disable Lint/ToJSON
          as_json.to_json
        end

        def update_application_url_mappings
          maps = ::Set.new
          NewRelic::Security::Agent.agent.route_map.each do |mapping| 
            method, path = mapping.split('@')
            maps << { :method => method, :path => path }
          end
          @mappings = maps.to_a
        end

        private 

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

      end
    end
  end
end