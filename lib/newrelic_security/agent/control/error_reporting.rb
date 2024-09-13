module NewRelic::Security
  module Agent
    module Control
      class ErrorReporting

        STATUS_CODES_5XX = {
          500 => "Internal Server Error",
          501 => "Not Implemented",
          502 => "Bad Gateway",
          503 => "Service Unavailable",
          504 => "Gateway Timeout",
          505 => "HTTP Version Not Supported",
          506 => "Variant Also Negotiates",
          507 => "Insufficient Storage",
          508 => "Loop Detected",
          509 => "Bandwidth Limit Exceeded",
          510 => "Not Extended",
          511 => "Network Authentication Required"
        }.freeze

        attr_accessor :exceptions_map
        
        def initialize
          @exceptions_map = {}
        end

        def generate_unhandled_exception(noticed_error, ctxt, response_code)
          unhandled_exception = {}
          category = nil
          if noticed_error
            unhandled_exception[:message] = noticed_error.message
            unhandled_exception[:cause] = nil
            unhandled_exception[:type] = noticed_error.exception_class_name
            unhandled_exception[:stackTrace] = noticed_error.stack_trace
            category = noticed_error.exception_class_name
          end
          category = STATUS_CODES_5XX[response_code] if response_code
          application_runtime_error = NewRelic::Security::Agent::Control::ApplicationRuntimeError.new(unhandled_exception, ctxt, response_code, category)
          key = if response_code
            ctxt.route&.split(AT_THE_RATE)&.[](1)&.+ response_code.to_s
                else
            application_runtime_error.exception[:type] + application_runtime_error.exception[:stackTrace][0]
                end
          application_runtime_error.counter += 1 if @exceptions_map.key?(key)
          @exceptions_map[key] = application_runtime_error
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in generating unhandled exception: #{exception.inspect} #{exception.backtrace}\n"
        end

        def extract_noticed_error(current_transaction, ctxt, response_code)
          # TODO: Below operation is expensive, talk to APM to get optimized way to do this
          current_transaction.exceptions.each do |_, span|
            current_transaction.segments.each do |segment|
              generate_unhandled_exception(segment.noticed_error, ctxt, response_code) if span[:span_id] == segment.guid
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in extract_noticed_error: #{exception.inspect} #{exception.backtrace}\n"
        end

        def report_unhandled_or_5xx_exceptions(current_transaction, ctxt, response_code = nil)
          if current_transaction.exceptions.empty? && response_code.between?(500, 599)
            generate_unhandled_exception(nil, ctxt, response_code)
          else
            extract_noticed_error(current_transaction, ctxt, response_code) unless current_transaction.exceptions.empty?
          end
        end

      end 
    end
  end
end