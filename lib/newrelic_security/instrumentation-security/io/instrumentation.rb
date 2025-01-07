require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module IO
      
      def open_on_enter(*args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = args[0].to_s
        if args[0].is_a? Integer
          fname = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[args[0].object_id.to_s].to_s if NewRelic::Security::Agent::Control::HTTPContext.get_context && NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.key?(args[0].object_id.to_s)
        else 
          fname = ::File.path(args[0]) if args[0] #some times it is 'String' or 'Path' class
        end
        abs_path = ::File.expand_path(fname)
        fmode = args[1]
        event_category = NewRelic::Security::Instrumentation::InstrumentationUtils::OPEN_MODES.include?(fmode) ? READ : WRITE
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_open?(fname, abs_path, fmode)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname], event_category)
        else
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname} #{fmode}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], event_category)
          end              
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event        
      end
      
      def open_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def new_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = var[0].to_s
        if var[0].is_a? Integer
          fname = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[var[0].object_id.to_s].to_s if NewRelic::Security::Agent::Control::HTTPContext.get_context && NewRelic::Security::Agent::Control::HTTPContext.get_context.cache.key?(var[0].object_id.to_s)
        else 
          fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        end
        abs_path = ::File.expand_path(fname)
        fmode = var[1] if var[1]
        event_category = NewRelic::Security::Instrumentation::InstrumentationUtils::OPEN_MODES.include?(fmode) ? READ : WRITE
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_open?(fname, abs_path, fmode)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname], event_category)
        else
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname} #{fmode}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], event_category)
          end          
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def new_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def sysopen_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def sysopen_on_exit(event, retval, *var)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[retval.object_id.to_s] = fname if NewRelic::Security::Agent::Control::HTTPContext.get_context
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def read_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
          NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{var}"
        else
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], READ)
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def read_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(String)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def binread_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
          NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{var}"
        else
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], READ)
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def binread_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(String)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def readlines_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
          NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{var}"
        else
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], READ)
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def readlines_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Array)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def foreach_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        abs_path = ::File.expand_path(fname)
        if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
          NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{var}"
        else
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], READ)
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def foreach_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(NilClass) || retval.is_a?(Enumerator)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def write_on_enter(*var, **kwargs)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        abs_path = ::File.expand_path(fname)
        fmode = kwargs.has_key?(:mode) ? kwargs[:mode] : WRITE
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_open?(fname, abs_path, fmode)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname], WRITE)
        else 
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname} #{fmode}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], WRITE)
          end 
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def write_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def binwrite_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(var[0]) #some times it is 'String' or 'Path' class
        abs_path = ::File.expand_path(fname)
        fmode = BINWRITE
        if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_open?(fname, abs_path, fmode)
          event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, [fname], WRITE)
        else
          if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
            NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname} #{fmode}"
          else
            event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, [fname], WRITE)
          end 
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end
      
      def binwrite_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def popen_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ic_args = []
        var.each { |arg| 
          if arg.is_a? String
            ic_args << arg
          elsif arg.is_a? Array
            ic_args << arg.join(" ")
          end 
        }
        event = NewRelic::Security::Agent::Control::Collector.collect(SYSTEM_COMMAND, ic_args)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield if block_given?
        return event
      end
      
      def popen_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:io, ::IO.singleton_class, ::NewRelic::Security::Instrumentation::IO)

