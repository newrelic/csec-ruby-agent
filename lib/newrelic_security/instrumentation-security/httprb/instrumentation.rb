require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module HTTPrb

      def perform_on_enter(request, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [request.uri.to_s])
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(options.headers, event) if event
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def perform_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:httprb, ::HTTP::Client, ::NewRelic::Security::Instrumentation::HTTPrb)
