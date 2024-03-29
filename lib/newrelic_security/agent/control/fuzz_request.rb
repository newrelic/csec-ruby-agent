module NewRelic::Security
  module Agent
    module Control
      class FuzzRequest
        attr_reader :id
        attr_accessor :request, :case_type

        def initialize(id)
          @id = id
          @request = nil
          @case_type = nil
        end
        
      end
    end
  end
end