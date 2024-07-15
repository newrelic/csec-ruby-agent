require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module PG::Connection

      def exec_on_enter(sql)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = sql
        hash[:parameters] = []
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], POSTGRES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def exec_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def async_exec_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = args[0]
        hash[:parameters] = []
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], POSTGRES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def async_exec_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def prepare_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[args[0].to_s] = args[1].to_s if NewRelic::Security::Agent::Control::HTTPContext.get_context
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def prepare_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def exec_prepared_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[args[0].to_s] if NewRelic::Security::Agent::Control::HTTPContext.get_context
        hash[:sql] = self.exec("select statement from pg_prepared_statements where name = '#{args[0]}'").getvalue(0,0) unless hash[:sql]
        hash[:parameters] = args[1].map(&:to_s)
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], POSTGRES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.delete(args[0].to_s) if NewRelic::Security::Agent::Control::HTTPContext.get_context
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def exec_prepared_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:pg, ::PG::Connection, ::NewRelic::Security::Instrumentation::PG::Connection)
