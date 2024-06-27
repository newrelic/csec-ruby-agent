require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module ActiveRecord::ConnectionAdapters::SQLite3Adapter

      def execute_on_enter(sql, name)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:sql] = sql  #sql query
        hash[:parameters] = []
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

      def exec_query_on_enter(*var, **key_vars)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        type_casted_binds = []
        binds = var[2] #third arg
        if !binds.nil? && !binds.empty? #if bind params present
          binds.each { |x|
            if x.is_a? Integer or x.is_a? String
              type_casted_binds << x
            elsif x.is_a? Array and x[0].is_a? ::ActiveRecord::ConnectionAdapters::Column
              type_casted_binds << x[1].to_s
            else
              type_casted_binds << x.value_before_type_cast.to_s
            end
          }
          # binds_copy = binds.clone  #it is a shallow copy
          # type_casted_binds = type_casted_binds(binds_copy.to_s)
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def exec_query_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def internal_exec_query_on_enter(*var, **key_vars)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        type_casted_binds = []
        binds = var[2] #third arg
        if !binds.nil? && !binds.empty? #if bind params present
          binds.each { |x|
            if x.is_a? Integer or x.is_a? String
              type_casted_binds << x
            elsif x.is_a? Array and x[0].is_a? ::ActiveRecord::ConnectionAdapters::Column
              type_casted_binds << x[1].to_s
            else
              type_casted_binds << x.value_before_type_cast.to_s
            end
          }
          # binds_copy = binds.clone  #it is a shallow copy
          # type_casted_binds = type_casted_binds(binds_copy.to_s)
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def internal_exec_query_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def exec_update_on_enter(*var, **key_vars)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        type_casted_binds = []
        binds = var[2] #third arg
        if !binds.nil? && !binds.empty? #if bind params present
          binds.each { |x|
            if x.is_a? Integer or x.is_a? String
              type_casted_binds << x
            elsif x.is_a? Array and x[0].is_a? ::ActiveRecord::ConnectionAdapters::Column
              type_casted_binds << x[1].to_s
            else
              type_casted_binds << x.value_before_type_cast.to_s
            end
          }
          # binds_copy = binds.clone  #it is a shallow copy
          # type_casted_binds = type_casted_binds(binds_copy.to_s)
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def exec_update_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def exec_delete_on_enter(*var, **key_vars)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        type_casted_binds = []
        binds = var[2] #third arg
        if !binds.nil? && !binds.empty? #if bind params present
          binds.each { |x|
            if x.is_a? Integer or x.is_a? String
              type_casted_binds << x
            elsif x.is_a? Array and x[0].is_a? ::ActiveRecord::ConnectionAdapters::Column
              type_casted_binds << x[1].to_s
            else
              type_casted_binds << x.value_before_type_cast.to_s
            end
          }
          # binds_copy = binds.clone  #it is a shallow copy
          # type_casted_binds = type_casted_binds(binds_copy.to_s)
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], SQLITE) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def exec_delete_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:sqlite3_adapter, ::ActiveRecord::ConnectionAdapters::SQLite3Adapter, ::NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::SQLite3Adapter)
