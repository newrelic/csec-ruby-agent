# frozen_string_literal: true

module NewRelic::Security::WebSocket
  module Frame
    module Handler
      autoload :Base,      "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler/base"

      autoload :Handler03, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler/handler03"
      autoload :Handler04, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler/handler04"
      autoload :Handler05, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler/handler05"
      autoload :Handler07, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler/handler07"
      autoload :Handler75, "#{NewRelic::Security::WebSocket::ROOT}/websocket/frame/handler/handler75"
    end
  end
end
