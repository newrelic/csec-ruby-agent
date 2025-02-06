module NewRelic::Security
  module Instrumentation
    module SecureRandomClass
      module Prepend
        include NewRelic::Security::Instrumentation::SecureRandomClass

        def gen_random(*args)
          retval = nil
          event = gen_random_on_enter { retval = super }
          gen_random_on_exit(event) { return retval }
        end
      end
    end
  end
end