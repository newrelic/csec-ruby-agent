require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Typhoeus
      module Request

        def run_on_enter
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [NewRelic::Security::Instrumentation::InstrumentationUtils.parse_typhoeus_request(self)])
          NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(self.options[:headers], event) if event
          event
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
          return event
        end

        def run_on_exit(event)
          NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
          NewRelic::Security::Agent::Utils.create_exit_event(event)
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
        end
      end


      module Hydra

        def run_on_enter
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          all_requests = []
          self.queued_requests.each {
            |request| 
            all_requests << NewRelic::Security::Instrumentation::InstrumentationUtils.parse_typhoeus_request(request)
          }
          event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, all_requests)
          self.queued_requests.each { |request| NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(request.options[:headers], event) } if event
          all_requests = nil
          event
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
          return event
        end

        def run_on_exit(event)
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
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:typhoeus, ::Typhoeus::Request, ::NewRelic::Security::Instrumentation::Typhoeus::Request)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:typhoeus, ::Typhoeus::Hydra, ::NewRelic::Security::Instrumentation::Typhoeus::Hydra)
