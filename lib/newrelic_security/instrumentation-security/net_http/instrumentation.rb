require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module NetHTTP

      HTTP = 'http'
      HTTP_COLON_SLASH_SLAH = 'http://'
      HTTPS_COLON_SLASH_SLAH = 'https://'


      def transport_request_on_enter(req)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
				uri = if req.uri && URI === req.uri
          req.uri.to_s
				      else
                "#{self.use_ssl? ? HTTPS_COLON_SLASH_SLAH : HTTP_COLON_SLASH_SLAH }#{self.address}:#{self.port}#{req.path}"
          end
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [uri])
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(req, event) if event
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def transport_request_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end
    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:net_http, ::Net::HTTP, ::NewRelic::Security::Instrumentation::NetHTTP)
