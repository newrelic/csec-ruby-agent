require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Mysql2::Client

      def prepare_on_enter(sql)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def prepare_on_exit(event, retval, sql)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[retval.object_id] = sql if NewRelic::Security::Agent::Control::HTTPContext.get_context
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

    end

    module Mysql2::Statement

      def execute_on_enter(*args, **kwargs)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[self.object_id] if NewRelic::Security::Agent::Control::HTTPContext.get_context
        hash[:parameters] = args.map(&:to_s)
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], MYSQL) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.delete(self.object_id) if NewRelic::Security::Agent::Control::HTTPContext.get_context
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def execute_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:mysql2, ::Mysql2::Client, ::NewRelic::Security::Instrumentation::Mysql2::Client)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:mysql2, ::Mysql2::Statement, ::NewRelic::Security::Instrumentation::Mysql2::Statement)
