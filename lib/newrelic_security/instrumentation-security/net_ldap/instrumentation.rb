require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module NetLDAP
      
      def search_on_enter(args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        if args.key?(:base) && !args[:base].empty?
          hash = {}
          hash[:name] = args[:base] if args.key?(:base)
          hash[:filter] = args[:filter] if args.key?(:filter)
          event = NewRelic::Security::Agent::Control::Collector.collect(LDAP, [hash])
        else
          #some times this method is also used during instance creation
          # to know the capabilities of Ldap server. In these
          # situations they don't provide the query parameter, so we filter
          # this event
          NewRelic::Security::Agent.logger.info "Filtered #{self.class}.#{__method__} because of insufficient args. args : #{args}\n"
        end
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def search_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:net_ldap, ::Net::LDAP, ::NewRelic::Security::Instrumentation::NetLDAP)
