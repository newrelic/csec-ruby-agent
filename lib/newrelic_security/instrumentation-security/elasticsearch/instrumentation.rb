require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Elasticsearch

      def perform_request_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:method] = args[0]
        hash[:path] = args[1]
        hash[:params] = args[2]
        hash[:body] = args[3].to_json
        hash[:headers] = args[4]
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], ES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def perform_request_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:elasticsearch, ::Elastic::Transport::Client, ::NewRelic::Security::Instrumentation::Elasticsearch)
