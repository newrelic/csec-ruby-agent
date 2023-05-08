require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module File

      def delete_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_delete?(var)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, var)
        else
          # TODO: Add handling read_filter for outside app root directory files, example ../abc.txt
          NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{var}"
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def delete_on_exit(event, retval)
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
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_delete?(var)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, var)
        else
          # TODO: Add handling read_filter for outside app root directory files, example ../abc.txt
          NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{var}"
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:file, ::File.singleton_class, ::NewRelic::Security::Instrumentation::File)
