require 'thread'

module NewRelic::Security
  module Agent
    module Control
      class EventCounter
        def initialize
          @mutex = Mutex.new
          @counter = 0
        end

        def increment
          @mutex.synchronize do
            @counter += 1
          end
        end

        def fetch_and_reset_counter
          @mutex.synchronize do
            old_count = @counter
            @counter = 0
            old_count
          end
        end
      end
    end
  end
end