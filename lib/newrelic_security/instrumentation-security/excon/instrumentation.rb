require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Excon::Connection

      def request_on_enter(params)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ob = {}
        ob[:Method] = params[:method]
        ob[:scheme]  = self.data[:scheme]
        ob[:host]    = self.data[:host]
        ob[:port]    = self.data[:port]
        ob[:URI]     = self.data[:query].nil? ? "#{self.data[:host]}#{self.data[:path]}" : "#{self.data[:host]}#{self.data[:path]}?#{self.data[:query]}"
        ob[:path]    = self.data[:path]
        ob[:query]   = self.data[:query]
        ob[:Body] = self.data[:body]
        ob[:Headers] = self.data[:headers]
        ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(self.data[:headers], event) if event
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def request_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:excon, ::Excon::Connection, ::NewRelic::Security::Instrumentation::Excon::Connection)
