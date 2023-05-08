module NewRelic::Security
  module Instrumentation
    module File
      module Prepend
        include ::NewRelic::Security::Instrumentation::File

        def delete(*var)
          retval = nil
          event = delete_on_enter(*var) { retval = super }
          delete_on_exit(event, retval) { return retval }
        end

        def unlink(*var)
          retval = nil
          event = unlink_on_enter(*var) { retval = super }
          unlink_on_exit(event, retval) { return retval }
        end

      end
    end
  end
end