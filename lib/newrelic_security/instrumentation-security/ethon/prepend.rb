module NewRelic::Security
  module Instrumentation
    module Ethon
      module Easy
        module Prepend
          include NewRelic::Security::Instrumentation::Ethon::Easy

          def fabricate(url, action_name, options)
            fabricate_on_enter(url, action_name, options) { return super }
          rescue Exception => e
            puts "exception in : #{e} #{e.backtrace}"
          end
  
          def headers=(headers)
            headers_equals_on_enter(headers) { return super }
          end

          def perform(*args)
            retval = nil
            event = perform_on_enter(*args) { retval = super }
            perform_on_exit(event) { return retval }
          end

        end
      end

      module Multi
        module Prepend
          include NewRelic::Security::Instrumentation::Ethon::Multi

          def perform(*args)
            retval = nil
            event = perform_on_enter(*args) { retval = super }
            perform_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end