require_relative 'prepend'
require_relative 'chain'

module NewRelic::Security
  module Instrumentation
    module Redis::Client

      READ_MODES = %i[get getrange mapped_mget mget strlen].freeze
      WRITE_MODES = %i[set mapped_mset mapped_msetnx mset msetnx psetex setex setnx].freeze
      DELETE_MODES = %i[getdel del].freeze
      UPDATE_MODES = %i[append decr decrby getex getset incr incrby incrbyfloat setrange].freeze

      def call_v_on_enter(command)
        event = nil
        NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
        hash = {}
        hash[:type] = command[0]
        hash[:arguments] = command[1..-1]
        if READ_MODES.include?(command[0])
          hash[:mode] = :read
        elsif WRITE_MODES.include?(command[0])
          hash[:mode] = :write
        elsif DELETE_MODES.include?(command[0])
          hash[:mode] = :delete
        elsif UPDATE_MODES.include?(command[0])
          hash[:mode] = :update
        end
        event = NewRelic::Security::Agent::Control::Collector.collect(CACHING_DATA_STORE, [hash], REDIS)
      rescue => exception
        NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
      ensure
        yield
        return event
      end

      def call_v_on_exit(event)
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

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:redis, ::Redis::Client, ::NewRelic::Security::Instrumentation::Redis::Client)
