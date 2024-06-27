require_relative 'prepend'
require_relative 'chain'
require 'uri'

module NewRelic::Security
  module Instrumentation
    module AsyncHttp

      def call_on_enter(method, url, headers, body)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ob = {}
        ob[:Method] = method
        uri = ::URI.parse url
        ob[:scheme]  = uri.scheme
        ob[:host]    = uri.host
        ob[:port]    = uri.port
        ob[:URI]     = uri.to_s
        ob[:path]    = uri.path
        ob[:query]   = uri.query
        ob[:Body] = body.respond_to?(:join) ? body.join.to_s : body.to_s
        ob[:Headers] = headers.to_h
        ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
        NewRelic::Security::Instrumentation::InstrumentationUtils.append_tracing_data(headers, event) if event
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def call_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:async_http, ::Async::HTTP::Internet, ::NewRelic::Security::Instrumentation::AsyncHttp)
