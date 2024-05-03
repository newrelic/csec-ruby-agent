require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module SQLite3::Database
      # TODO: When bind_param(index, value) is called and then execute is called directly in such case bind_params found are nil because bind_param method is in ext c file.
      def execute_on_enter(sql, bind_vars, *args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = sql
        hash[:parameters] = bind_vars.is_a?(String) ? [bind_vars] : bind_vars.map(&:to_s)
        hash[:parameters] = hash[:parameters] + args unless args.empty?
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
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

      def execute_batch_on_enter(sql, bind_vars, *args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = sql
        hash[:parameters] = bind_vars.is_a?(String) ? [bind_vars] : bind_vars.map(&:to_s)
        hash[:parameters] = hash[:parameters] + args unless args.empty?
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def execute_batch_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def execute_batch2_on_enter(sql)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = sql
        hash[:parameters] = []
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def execute_batch2_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

    end

    module SQLite3::Statement

      def initialize_on_enter(db, sql)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def initialize_on_exit(event, retval, sql)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[retval.object_id] = { :sql => sql } if NewRelic::Security::Agent::Control::HTTPContext.get_context
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def bind_params_on_enter(*bind_vars)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[self.object_id][:parameters] = bind_vars.map(&:to_s) if NewRelic::Security::Agent::Control::HTTPContext.get_context && NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.key?(self.object_id)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def bind_params_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def execute_on_enter(*bind_vars)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ic_args = []
        key = self.object_id
        if NewRelic::Security::Agent::Control::HTTPContext.get_context && NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.key?(self.object_id)
          if bind_vars.length == 0
            ic_args.push(NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[key])
          else
            hash = {}
            hash[:sql] = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[key][:sql]
            hash[:parameters] = bind_vars.map(&:to_s)
            ic_args.push(hash)
          end
        end
        if ic_args[0].has_key?(:sql)
          event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, ic_args, SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(ic_args[0][:sql])
        else
          event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, ic_args, SQLITE)
        end
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.delete(key) if NewRelic::Security::Agent::Control::HTTPContext.get_context
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:sqlite3, ::SQLite3::Database, ::NewRelic::Security::Instrumentation::SQLite3::Database)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:sqlite3, ::SQLite3::Statement, ::NewRelic::Security::Instrumentation::SQLite3::Statement)
