require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module HTTPX::Session

      def send_requests_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ic_args = []
        args.each do |arg|
          ob = {}
          ob[:Method] = arg.verb
          uri = arg.uri
          ob[:scheme]  = uri.scheme
          ob[:host]    = uri.host
          ob[:port]    = uri.port
          ob[:URI]     = uri.to_s
          ob[:path]    = uri.path
          ob[:query]   = uri.query
          ob[:Body]    = arg.body.bytesize.positive? ? arg.body.to_s : ""
          ob[:Headers] = arg.headers
          ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
          ic_args << ob
        end
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, ic_args)
        args.each do |arg|
          NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(arg.headers, event) if event
        end
        event
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def send_requests_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:httpx, ::HTTPX::Session, ::NewRelic::Security::Instrumentation::HTTPX::Session)
