# frozen_string_literal: true

module NewRelic::Security::WebSocket
  module Handshake
    module Handler
      autoload :Base,     "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/base"

      autoload :Client,   "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/client"
      autoload :Client01, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/client01"
      autoload :Client04, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/client04"
      autoload :Client11, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/client11"
      autoload :Client75, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/client75"
      autoload :Client76, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/client76"

      autoload :Server,   "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/server"
      autoload :Server04, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/server04"
      autoload :Server75, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/server75"
      autoload :Server76, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler/server76"
    end
  end
end
