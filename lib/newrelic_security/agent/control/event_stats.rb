module NewRelic::Security
  module Agent
    module Control
      class EventStats

        attr_accessor :processed, :sent, :rejected, :error_count

        def initialize
          @processed = NewRelic::Security::Agent::Control::EventCounter.new
          @sent = NewRelic::Security::Agent::Control::EventCounter.new
          @rejected = NewRelic::Security::Agent::Control::EventCounter.new
          @error_count = NewRelic::Security::Agent::Control::EventCounter.new
        end

        def prepare_for_health_check
          hash = {}
          hash[:processed] = @processed.fetch_and_reset_counter
          hash[:sent] = @sent.fetch_and_reset_counter
          hash[:rejected] = @rejected.fetch_and_reset_counter
          hash[:errorCount] = @error_count.fetch_and_reset_counter
          hash
        end
      end
    end
  end
end