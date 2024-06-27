module NewRelic::Security
  module Instrumentation
    module Ethon
      module Easy
        module Chain
          def self.instrument!
            ::Ethon::Easy.class_eval do
              include NewRelic::Security::Instrumentation::Ethon::Easy

              alias_method :fabricate_without_security, :fabricate
    
              def fabricate(url, action_name, options)
                fabricate_on_enter(url, action_name, options) { return fabricate_without_security(url, action_name, options) }
              end

              alias_method(:headers_equals_without_security, :headers=)
    
              def headers=(headers)
                headers_equals_on_enter(headers) { return headers_equals_without_security(headers) }
              end

              alias_method :perform_without_security, :perform
    
              def perform(*args)
                retval = nil
                event = perform_on_enter(*args) { retval = perform_without_security(*args) }
                perform_on_exit(event) { return retval }
              end
            end
          end
        end
      end

      module Multi
        module Chain
          def self.instrument!
            ::Ethon::Multi.class_eval do
              include NewRelic::Security::Instrumentation::Ethon::Multi

              alias_method :perform_without_security, :perform
    
              def perform(*args)
                retval = nil
                event = perform_on_enter(*args) { retval = perform_without_security(*args) }
                perform_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end