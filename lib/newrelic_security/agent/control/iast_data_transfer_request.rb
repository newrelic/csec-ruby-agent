require 'json'
require 'set'

module NewRelic::Security
  module Agent
    module Control
      class IASTDataTransferRequest
        attr_reader :jsonName
        attr_accessor :batchSize, :completedReplay, :errorInReplay, :clearFromPending, :generatedEvent

        def initialize
          @jsonName = :'iast-data-request'
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @batchSize = 10
          @completedReplay = ::Set.new
          @errorInReplay = ::Set.new
          @clearFromPending = ::Set.new
          @generatedEvent = {}
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