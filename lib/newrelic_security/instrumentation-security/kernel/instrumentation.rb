require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Kernel

      def require_on_enter(name)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def require_on_exit(event, retval, name)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        if retval
          NewRelic::Security::Agent.logger.info "Dynamic loading of #{name} module observed, TODO: Call Instrumentation API"
           # TODO: Call Instrumentation API here (Dynamic loading of module observed)
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def system_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ic_args = []
        var.each { |arg| 
          ic_args << arg if arg.is_a? String
        }
        event = NewRelic::Security::Agent::Control::Collector.collect(SYSTEM_COMMAND, ic_args)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def system_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def backtick_on_enter(cmd)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        event = NewRelic::Security::Agent::Control::Collector.collect(SYSTEM_COMMAND, Array(cmd))
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def backtick_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if $? && $?.exitstatus == 0
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def spawn_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        ic_args = []
        var.each { |arg| 
          ic_args << arg if arg.is_a? String
        }
        event = NewRelic::Security::Agent::Control::Collector.collect(SYSTEM_COMMAND, ic_args)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def spawn_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def exec_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        event = NewRelic::Security::Agent::Control::Collector.collect(SYSTEM_COMMAND, var)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def exec_on_exit(event)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent.logger.debug "Exit event : #{event}"
        # TODO: Add exit event if required
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      def open_on_enter(*args, **kwargs)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        fname = ::File.path(args[0]) #some times it is 'String' or 'Path' class
        if fname.start_with?(PIPE)
          event = NewRelic::Security::Agent::Control::Collector.collect(SYSTEM_COMMAND, args)
        else
          abs_path = ::File.expand_path(fname)
          if args.length == 2
            fmode = args[1]
            event_category = NewRelic::Security::Instrumentation::InstrumentationUtils::OPEN_MODES.include?(fmode) ? READ : WRITE
            if NewRelic::Security::Instrumentation::InstrumentationUtils.notify_app_integrity_open?(fname, abs_path, fmode)
              event = NewRelic::Security::Agent::Control::Collector.collect(FILE_INTEGRITY, Array(fname), event_category)
            else
              if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
                NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{fname} #{fmode}"
              else
                event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, Array(fname), event_category)
              end
            end
          else
            if NewRelic::Security::Instrumentation::InstrumentationUtils.read_filter?(fname, abs_path)
              NewRelic::Security::Agent.logger.debug "Filtered because File name exist in filtered list #{self.class}.#{__method__} Args:: #{args}"
            else
              event = NewRelic::Security::Agent::Control::Collector.collect(FILE_OPERATION, Array(fname), READ)
            end
          end
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def open_on_exit(event, retval)
        NewRelic::Security::Agent.logger.debug "OnExit :  #{self.class}.#{__method__}"
        NewRelic::Security::Agent::Utils.create_exit_event(event) if retval.is_a?(Integer)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
      end

      unless NewRelic::Security::Agent.config[:'security.exclude_from_iast_scan.iast_detection_category.insecure_settings']
        def rand_on_enter
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          event = NewRelic::Security::Agent::Control::Collector.collect(RANDOM, [KERNEL], RANDOM)
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
          return event
        end

        def rand_on_exit(event)
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
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:kernel, ::Object, ::NewRelic::Security::Instrumentation::Kernel)
