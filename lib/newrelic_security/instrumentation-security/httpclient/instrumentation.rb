require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module HTTPClient

      def do_request_on_enter(method, uri, query, body, header)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ob = {}
        ob[:Method] = method
        unless uri.nil?
          ob[:scheme]  = uri.scheme
          ob[:host]    = uri.host
          ob[:port]    = uri.port
          ob[:URI]     = uri.to_s
          ob[:path]    = uri.path
          ob[:query]   = uri.query
        end
        ob[:Body] = body
        ob[:Headers] = header
        ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(header, event) if event
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def do_request_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def do_request_async_on_enter(method, uri, query, body, header)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ob = {}
        ob[:Method] = method
        unless uri.nil?
          ob[:scheme]  = uri.scheme
          ob[:host]    = uri.host
          ob[:port]    = uri.port
          ob[:URI]     = uri.to_s
          ob[:path]    = uri.path
          ob[:query]   = uri.query
        end
        ob[:Body] = body
        ob[:Headers] = header
        ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(header, event) if event
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def do_request_async_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:httpclient, ::HTTPClient, ::NewRelic::Security::Instrumentation::HTTPClient)
