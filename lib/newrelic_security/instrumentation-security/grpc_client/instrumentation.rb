require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module GRPC
      module ClientStub
        def request_response_on_enter(method, req, marshal, unmarshal, deadline, return_op, parent, credentials, metadata) # rubocop:disable Metrics/ParameterLists
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          host = "grpc://#{instance_variable_get(:@host)}#{method}"
          event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [host])
          NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(metadata, event) if event
          event
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
          return event
        end
  
        def request_response_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:gRPC_Client, ::GRPC::ClientStub, ::NewRelic::Security::Instrumentation::GRPC::ClientStub)
