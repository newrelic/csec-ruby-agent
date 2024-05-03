module NewRelic::Security
  module Instrumentation
    module NetLDAP
      module Prepend
        include NewRelic::Security::Instrumentation::NetLDAP

        def search(args = {}, &block)
          retval = nil
          event = search_on_enter(args) { retval = super }
          search_on_exit(event) { return retval }
        end

      end
    end
  end
end