module NewRelic::Security
  module Instrumentation
    module DigestClass
      module Chain
        def self.instrument!
          ::Digest::Class.class_eval do
            class << self
              include ::NewRelic::Security::Instrumentation::DigestClass

              alias_method :digest_without_security, :digest
    
              def digest(string, *parameters)
                return digest_without_security(string, *parameters) if string.include?(NEWRELIC_SECURITY)
                retval = nil
                event = digest_on_enter { retval = digest_without_security(string, *parameters) }
                digest_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end