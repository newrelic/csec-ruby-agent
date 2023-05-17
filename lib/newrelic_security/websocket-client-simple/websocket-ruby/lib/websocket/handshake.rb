# frozen_string_literal: true

module NewRelic::Security::WebSocket
  module Handshake
    autoload :Base,    "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/base"
    autoload :Client,  "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/client"
    autoload :Handler, "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/handler"
    autoload :Server,  "#{NewRelic::Security::WebSocket::ROOT}/websocket/handshake/server"
  end
end
