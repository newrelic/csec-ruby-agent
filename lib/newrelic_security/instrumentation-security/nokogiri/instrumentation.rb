require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Nokogiri::XML

      def xpath_on_enter(*var)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        paths, _, _, binds = extract_params(var)
        hash = { :paths => paths, :variables => binds }
        event = NewRelic::Security::Agent::Control::Collector.collect(XPATH, [hash])
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def xpath_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:nokogiri, ::Nokogiri::XML::Node, ::NewRelic::Security::Instrumentation::Nokogiri::XML::Node)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:nokogiri, ::Nokogiri::XML::NodeSet, ::NewRelic::Security::Instrumentation::Nokogiri::XML::NodeSet)

# TODO: check if this hook can replace both the hooks, Nokogiri::XML::Searchable#xpath
