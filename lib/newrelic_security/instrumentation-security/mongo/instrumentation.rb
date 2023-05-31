require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Mongo::Collection

      def find_on_enter(filter, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = filter
        hash[:payload][:options] = options
        hash[:payloadType] = :find #bind params
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def find_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def insert_one_on_enter(document, opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        if caller_locations[1].label.to_s == "insert_one_with_clear_cache"
          NewRelic::Security::Agent.logger.debug "Filtered to break the loop calling #{self.class}.#{__method__} from 'insert_one_with_clear_cache'"
          return
        end
        hash = {}
        hash[:payload] = {}
        hash[:payload][:document] = document
        hash[:payload][:opts] = opts
        hash[:payloadType] = :insert
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def insert_one_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def insert_many_on_enter(documents, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:documents] = documents
        hash[:payload][:options] = options
        hash[:payloadType] = :insert
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def insert_many_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def update_one_on_enter(filter, update, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = filter
        hash[:payload][:update] = update
        hash[:payload][:options] = options
        hash[:payloadType] = :update
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def update_one_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def update_many_on_enter(filter, update, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = filter
        hash[:payload][:update] = update
        hash[:payload][:options] = options
        hash[:payloadType] = :update
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def update_many_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def delete_one_on_enter(filter, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = filter
        hash[:payload][:options] = options
        hash[:payloadType] = :delete
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def delete_one_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def delete_many_on_enter(filter, options)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = filter
        hash[:payload][:options] = options
        hash[:payloadType] = :delete
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def delete_many_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

    end

    module Mongo::Collection::View
      def update_one_on_enter(spec, opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:spec] = spec
        hash[:payload][:opts] = opts
        hash[:payloadType] = :update
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def update_one_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def update_many_on_enter(spec, opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:spec] = spec
        hash[:payload][:opts] = opts
        hash[:payloadType] = :update
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def update_many_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def delete_one_on_enter(opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:opts] = opts
        hash[:payloadType] = :delete
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def delete_one_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def find_one_and_delete_on_enter(opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:opts] = opts
        hash[:payloadType] = :delete
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def find_one_and_delete_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def delete_many_on_enter(opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:opts] = opts
        hash[:payloadType] = :delete
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def delete_many_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def replace_one_on_enter(replacement, opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:replacement] = replacement
        hash[:payload][:opts] = opts
        hash[:payloadType] = :update
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def replace_one_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def find_one_and_update_on_enter(document, opts)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:payload] = {}
        hash[:payload][:filter] = instance_variable_get(:@filter)
        hash[:payload][:document] = document
        hash[:payload][:opts] = opts
        hash[:payloadType] = :update
        event = NewRelic::Security::Agent::Control::Collector.collect(NOSQL_DB_COMMAND, [hash], MONGO)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def find_one_and_update_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:mongo, ::Mongo::Collection, ::NewRelic::Security::Instrumentation::Mongo::Collection)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:mongo, ::Mongo::Collection::View, ::NewRelic::Security::Instrumentation::Mongo::Collection::View)
