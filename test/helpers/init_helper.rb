# Create agent
module NewRelic::Security
  module Agent
    class Agent
      def initialize
        create_agent_home
        @started = true
        @route_map = []
        @http_request_count = NewRelic::Security::Agent::Control::EventCounter.new
      end
    end
  end
end