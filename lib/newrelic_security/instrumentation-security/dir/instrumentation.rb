require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Dir

      def mkdir_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = var[0]
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_open?(fname, abs_path, WRITE)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname])
        else
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname])
          end 
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def mkdir_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def rmdir_on_enter(name)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = name
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_delete?([fname])
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname])
        else
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname])
          end 
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def rmdir_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def unlink_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = var[0]
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_delete?([fname])
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname])
        else
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname])
          end 
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def unlink_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end
      
    end
  end
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:dir, ::Dir.singleton_class, ::NewRelic::Security::Instrumentation::Dir)
