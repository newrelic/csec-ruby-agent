module NewRelic::Security
  module Instrumentation
    module Dir
      module Prepend
        include ::NewRelic::Security::Instrumentation::Dir

        def mkdir(*var)
          retval = nil
          event = mkdir_on_enter(*var) { retval = super }
          mkdir_on_exit(event, retval) { return retval }
        end

        def rmdir(name)
          retval = nil
          event = rmdir_on_enter(name) { retval = super }
          rmdir_on_exit(event, retval) { return retval }
        end

        def unlink(name)
          retval = nil
          event = unlink_on_enter(name) { retval = super }
          unlink_on_exit(event, retval) { return retval }
        end

      end
    end
  end
end