require_relative 'prepend'
require_relative 'chain'
require 'uri'

module NewRelic::Security
  module Instrumentation
    module Ethon
      module Easy

        def fabricate_on_enter(url, action_name, options)
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[self.object_id] = { :method => action_name } if NewRelic::Security::Agent::Control::HTTPContext.get_context
          NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[self.object_id][:body] = options[:body] if NewRelic::Security::Agent::Control::HTTPContext.get_context
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
        end

        def headers_equals_on_enter(headers)
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[self.object_id][:headers] = headers if NewRelic::Security::Agent::Control::HTTPContext.get_context
        rescue => exception
          NewRelic::Security::Agent.logger.error "Exception in hook in #{self.class}.#{__method__}, #{exception.inspect}, #{exception.backtrace}"
        ensure
          yield
        end

        def perform_on_enter(*args)
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          context = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[self.object_id] if NewRelic::Security::Agent::Control::HTTPContext.get_context
          uri = ::URI.parse(url)
          ob = {}
          ob[:Method] = context[:method] if context
          ob[:scheme] = uri.scheme
          ob[:host] = uri.host
          ob[:port] = uri.port
          ob[:URI] = uri.to_s
          ob[:path] = uri.path
          ob[:query] = uri.query
          ob[:Body] = context[:body] if context
          ob[:Headers] = context[:headers] if context
          ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
          event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, [ob])
          headers_copy = {}
          headers_copy.merge!(context[:headers]) if context&.key?(:headers)
          NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(headers_copy, event) if event
          self.headers = headers_copy if self.headers 
          event
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

      module Multi

        def perform_on_enter(*args)
          event = nil
          NewRelic::Security::Agent.logger.debug "OnEnter : #{self.class}.#{__method__}"
          ic_args = []
          easy_handles.each do |easy|
            context = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[easy.object_id] if NewRelic::Security::Agent::Control::HTTPContext.get_context
            uri = ::URI.parse(easy.url)
            ob = {}
            ob[:Method] = context[:method] if context
            ob[:scheme] = uri.scheme
            ob[:host] = uri.host
            ob[:port] = uri.port
            ob[:URI] = easy.url.to_s
            ob[:path] = uri.path
            ob[:query] = uri.query
            ob[:Body] = context[:body] if context
            ob[:Headers] = context[:headers] if context
            ob.each { |_, value| value.dup.force_encoding(ISO_8859_1).encode(UTF_8) if value.is_a?(String) }
            ic_args << ob
          end
          event = NewRelic::Security::Agent::Control::Collector.collect(HTTP_REQUEST, ic_args)
          easy_handles.each do |easy|
            context = NewRelic::Security::Agent::Control::HTTPContext.get_context.cache[easy.object_id] if NewRelic::Security::Agent::Control::HTTPContext.get_context
            headers_copy = {}
            headers_copy.merge!(context[:headers]) if context.key?(:headers)
            NewRelic::Security::Instrumentation::InstrumentationUtils.add_tracing_data(headers_copy, event) if event
            easy.headers = headers_copy
          end
          event
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
end

NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:ethon, ::Ethon::Easy, ::NewRelic::Security::Instrumentation::Ethon::Easy)
NewRelic::Security::Instrumentation::InstrumentationLoader.install_instrumentation(:ethon, ::Ethon::Multi, ::NewRelic::Security::Instrumentation::Ethon::Multi)
