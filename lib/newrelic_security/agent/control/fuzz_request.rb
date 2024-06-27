module NewRelic::Security
  module Agent
    module Control
      class FuzzRequest
        attr_reader :id
        attr_accessor :request, :case_type, :reflected_metadata

        def initialize(id)
          @id = id
          @request = nil
          @case_type = nil
          @reflected_metadata = nil
        end
        
      end
    end
  end
end