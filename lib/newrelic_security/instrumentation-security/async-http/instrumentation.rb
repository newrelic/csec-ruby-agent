require_relative 'prepend'
require_relative 'chain'
require 'uri'

module NewRelic::Security
  module Instrumentation
    module AsyncHttp

      def call_on_enter(_method, url, headers, _body)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        uri = ::URI.parse url
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [uri.to_s])
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
