require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module GraphQL::Query::Executor
      
      GRAPHQL_QUERY = 'GRAPHQL_QUERY'.freeze
      GRAPHQL_VARIABLE = 'GRAPHQL_VARIABLE'.freeze
      STAR_DOT_QUERY = '*.query'.freeze
      STAR_DOT_VARIABLES = '*.variables'.freeze

      def execute_on_enter
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ctxt = NewRelic::Security::Agent::Control::HTTPContext.get_context
        ctxt.custom_data_type[STAR_DOT_QUERY] = GRAPHQL_QUERY if query.query_string
        ctxt.custom_data_type[STAR_DOT_VARIABLES] = GRAPHQL_VARIABLE if query.instance_variable_get(:@provided_variables)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:graphql, ::GraphQL::Query::Executor, ::NewRelic::Security::Instrumentation::GraphQL::Query::Executor)
