module NewRelic::Security
  module Instrumentation
    module DigestClass
      module Prepend
        include NewRelic::Security::Instrumentation::DigestClass
        
        def digest(string, *parameters)
          return super if string.include?(NEWRELIC_SECURITY)
          retval = nil
          event = digest_on_enter { retval = super }
          digest_on_exit(event) { return retval }
        end
      end
    end
  end
end