require_relative 'prepend'
require_relative 'chain'

require 'uri'

module NewRelic::Security
  module Instrumentation
    module Patron::Session

      def request_on_enter(action, url, headers, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ob = {}
        ob[:Method] = action
        final_url = self.base_url.nil? ? url : "#{self.base_url}#{url}"
        uri = NewRelic::Security::Instrumentation::InstrumentationUtils.parse_uri(final_url)
        if uri
          ob[:scheme]  = uri.scheme
          ob[:host]    = uri.host
          ob[:port]    = uri.port
          ob[:URI]     = uri.to_s
          ob[:path]    = uri.path
          ob[:query]   = uri.query
          ob[:Body] = options[:data]
          ob[:Headers] = headers
          ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
          event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
        end
        NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(headers, event) if event
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:patron, ::Patron::Session, ::NewRelic::Security::Instrumentation::Patron::Session)
