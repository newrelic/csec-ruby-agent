require 'json'

module NewRelic::Security
  module Agent
    module Control
      class FuzzFailEvent
        attr_accessor :fuzzHeader
        attr_reader :jsonName

        def initialize
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :fuzzfail
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @policyVersion = nil
          @framework = NewRelic::Security::Agent.config[:framework]
          @fuzzHeader = nil
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