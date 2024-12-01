require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Dalli::Client

      READ_MODES = %i[get fetch].freeze
      WRITE_MODES = %i[set].freeze
      DELETE_MODES = %i[delete flush].freeze
      UPDATE_MODES = %i[get append prepend incr decr touch replace].freeze

      def perform_on_enter(*all_args)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:type] = all_args[0]
        hash[:arguments] = all_args[1..-1]
        if READ_MODES.include?(all_args[0])
          hash[:mode] = :read
        elsif WRITE_MODES.include?(all_args[0])
          hash[:mode] = :write
        elsif DELETE_MODES.include?(all_args[0])
          hash[:mode] = :delete
        elsif UPDATE_MODES.include?(all_args[0])
          hash[:mode] = :update
        end
        event = NewRelic::Security::Agent::Control::Collector.collect(CACHING_DATA_STORE, [hash], MEMCACHED)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def perform_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:memcached, ::Dalli::Client, ::NewRelic::Security::Instrumentation::Dalli::Client)
