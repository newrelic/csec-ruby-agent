require 'json'

module NewRelic::Security
  module Agent
    module Control
      class ExitEvent
        attr_accessor :executionId, :caseType, :k2RequestIdentifier
        attr_reader :jsonName
        
        def initialize
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :'exit-event'
          @collectorVersion =  NewRelic::Security::VERSION
          @buildNumber = nil
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @nodeId = nil
          @customerId = nil
          @emailId = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @policyVersion = nil
          @framework = NewRelic::Security::Agent.config[:framework]
          @executionId = nil
          @caseType = nil
          @k2RequestIdentifier = nil
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json
          as_json.to_json
        end
      end
    end
  end
end