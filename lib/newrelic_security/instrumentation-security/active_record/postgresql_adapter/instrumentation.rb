require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module ActiveRecord::ConnectionAdapters::PostgreSQLAdapter

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
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], POSTGRES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
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

      def exec_update_on_enter(*var)
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
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], POSTGRES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
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

      def exec_delete_on_enter(*var)
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
        end
        hash = {}
        hash[:sql] = var[0]  #sql query
        hash[:parameters] = type_casted_binds #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(SQL_DB_COMMAND, [hash], POSTGRES) unless NewRelic::Security::Instrumentation::InstrumentationUtils.sql_filter_events?(hash[:sql])
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:postgresql_adapter, ::ActiveRecord::ConnectionAdapters::PostgreSQLAdapter, ::NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::PostgreSQLAdapter)
