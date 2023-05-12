# frozen_string_literal: true

module NewRelic::Security::WebSocket
  module Frame
    class Outgoing
      class Server < Outgoing
        def incoming_masking?
          @handler.masking?
        end

        def outgoing_masking?
          false
        end
      end
    end
  end
end
