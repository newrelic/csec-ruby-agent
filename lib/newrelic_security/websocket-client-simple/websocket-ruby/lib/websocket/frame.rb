# frozen_string_literal: true

module NewRelic::Security::WebSocket
  module Frame
    autoload :Base,     "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/base"
    autoload :Data,     "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/data"
    autoload :Handler,  "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler"
    autoload :Incoming, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/incoming"
    autoload :Outgoing, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/outgoing"
  end
end
