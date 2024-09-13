require 'json'

module NewRelic::Security
  module Agent
    module Control
      class ErrorReporting

        attr_accessor :exceptions_map
        
        def initialize
          @exceptions_map = {}
        end

        def generate_unhandled_exception(noticed_error, ctxt)
          if noticed_error
            unhandled_exception = {}
            unhandled_exception[:message] = noticed_error.message
            unhandled_exception[:cause] = nil
            unhandled_exception[:type] = noticed_error.exception_class_name
            unhandled_exception[:stackTrace] = noticed_error.stack_trace
            
            application_runtime_error = NewRelic::Security::Agent::Control::ApplicationRuntimeError.new(unhandled_exception, ctxt, nil, noticed_error.exception_class_name)
            
            key = application_runtime_error.exception[:type] + application_runtime_error.exception[:stackTrace][0]
            application_runtime_error.counter += 1 if @exceptions_map.key?(key)
            @exceptions_map[key] = application_runtime_error
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in generating unhandled exception: #{exception.inspect} #{exception.backtrace}\n"
        end

        def extract_noticed_error(current_transaction, ctxt)
          current_transaction.exceptions.each do |_, span|
            current_transaction.segments.each do |segment|
              generate_unhandled_exception(segment.noticed_error, ctxt) if span[:span_id] == segment.guid
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in extract_noticed_error: #{exception.inspect} #{exception.backtrace}\n"
        end

        def generate_5xx_exception; end

      end 
    end
  end
end