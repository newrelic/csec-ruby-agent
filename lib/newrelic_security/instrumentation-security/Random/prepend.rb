module NewRelic::Security
  module Instrumentation
    module RandomClass
      module Prepend
        include NewRelic::Security::Instrumentation::RandomClass

        def rand(*args)
          retval = nil
          event = rand_on_enter { retval = super }
          rand_on_exit(event) { return retval }
        end
      end
    end
  end
end