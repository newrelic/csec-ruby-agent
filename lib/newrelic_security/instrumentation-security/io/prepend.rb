module NewRelic::Security
  module Instrumentation
    module IO
      module Prepend
        include NewRelic::Security::Instrumentation::IO
        if RUBY_VERSION < '2.7.0'
          def open(var1, var2 = "r", *var3, &var4)
            retval = nil
            event = open_on_enter(var1, var2) { retval = super }
            open_on_exit(event) { return retval }
          end
        else
          def open(*args, **kwargs, &block)
            retval = nil
            event = open_on_enter(*args) { retval = super }
            open_on_exit(event) { return retval }
          end
        end

        def read(*var, **kwargs)
          retval = nil
          event = read_on_enter(*var) { retval = super }
          read_on_exit(event, retval) { return retval }
        end

        def binread(*var)
          retval = nil
          event = binread_on_enter(*var) { retval = super }
          binread_on_exit(event, retval) { return retval }
        end

        def readlines(*var, **kwargs)
          retval = nil
          event = readlines_on_enter(*var) { retval = super }
          readlines_on_exit(event, retval) { return retval }
        end

        def new(*var, **kwargs)
          retval = nil
          event = new_on_enter(*var) { retval = super }
          new_on_exit(event) { return retval }
        end

        def sysopen(*var)
          retval = nil
          event = sysopen_on_enter(*var) { retval = super }
          sysopen_on_exit(event, retval, *var) { return retval }
        end

        def foreach(*var)
          retval = nil
          event = foreach_on_enter(*var) { retval = super }
          foreach_on_exit(event, retval) { return retval }
        end

        def write(*var, **kwargs)
          retval = nil
          event = write_on_enter(*var, **kwargs) { retval = super }
          write_on_exit(event, retval) { return retval }
        end

        def binwrite(*var)
          retval = nil
          event = binwrite_on_enter(*var) { retval = super }
          binwrite_on_exit(event, retval) { return retval }
        end

        def popen(*var)
          retval = nil
          event = popen_on_enter(*var) { retval = super }
          popen_on_exit(event) { return retval }
        end
      end
    end
  end
end