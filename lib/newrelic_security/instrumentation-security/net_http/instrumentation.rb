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
        ob = {}
				ob[:Method] = req.method
				if req.uri != nil && URI === req.uri
					uri = req.uri
					ob[:scheme]  = uri.scheme
					ob[:host]    = uri.host
					ob[:port]    = uri.port
					ob[:URI]     = uri.to_s
					ob[:path]    = uri.path
					ob[:query]   = uri.query
				else
					ob[:scheme]  = self.use_ssl? ? HTTPS : HTTP
					ob[:host]    = self.address
					ob[:port]    = self.port
					ob[:path]    = req.path
					ob[:query]   = nil
					ob[:URI] = "#{self.use_ssl? ? HTTPS_COLON_SLASH_SLAH : HTTP_COLON_SLASH_SLAH }#{self.address}:#{self.port}#{req.path}"
				end
				ob[:Body] = req.body
				ob[:Headers] = req.to_hash.transform_values! { |v| v.join}
        ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(req, event) if event
        ob = nil
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
