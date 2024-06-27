require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Curl::Multi

      def perform_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ic_args = []
        self.requests.each {
          |key, req|
          uri = NewRelic::Security::Instrumentation::InstrumentationUtils.parse_uri(req.url)
          ob = {}
          if uri
            ob[:Method]  = nil
            ob[:scheme]  = uri.scheme
            ob[:host]    = uri.host
            ob[:port]    = uri.port
            ob[:URI]     = uri.to_s
            ob[:path]    = uri.path
            ob[:query]   = uri.query
            ob[:Body]    = req.post_body
            ob[:Headers] = req.headers
            ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
            ic_args.push(ob)
          end
        }
        event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, ic_args)
        self.requests.each { |key, req| NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(req.headers, event) } if event
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:curb, ::Curl::Multi, ::NewRelic::Security::Instrumentation::Curl::Multi)
