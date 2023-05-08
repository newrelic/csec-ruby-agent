module NewRelic::Security
  module Instrumentation
    module IO
      module Chain
        def self.instrument!
          ::IO.class_eval do
            class << self
              include NewRelic::Security::Instrumentation::IO

              alias_method :open_without_security, :open

              if RUBY_VERSION < '2.7.0'
                def open(var1, var2 = "r", *var3, &var4)
                  retval = nil
                  event = open_on_enter(var1, var2) { retval = open_without_security(var1, var2, *var3, &var4) }
                  open_on_exit(event) { return retval }
                end
              else
                def open(*args, **kwargs, &block)
                  retval = nil
                  event = open_on_enter(*args) { retval = open_without_security(*args, **kwargs, &block) }
                  open_on_exit(event) { return retval }
                end
              end
              
              alias_method :read_without_security, :read

              def read(*var)
                retval = nil
                event = read_on_enter(*var) { retval = read_without_security(*var) }
                read_on_exit(event, retval) { return retval }
              end
              
              alias_method :binread_without_security, :binread

              def binread(*var)
                retval = nil
                event = binread_on_enter(*var) { retval = binread_without_security(*var) }
                binread_on_exit(event, retval) { return retval }
              end

              alias_method :readlines_without_security, :readlines

              def readlines(*var)
                retval = nil
                event = readlines_on_enter(*var) { retval = readlines_without_security(*var) }
                readlines_on_exit(event, retval) { return retval }
              end

              alias_method :new_without_security, :new

              def new(*var)
                retval = nil
                event = new_on_enter(*var) { retval = new_without_security(*var) }
                new_on_exit(event) { return retval }
              end

              alias_method :sysopen_without_security, :sysopen

              def sysopen(*var)
                retval = nil
                event = sysopen_on_enter(*var) { retval = sysopen_without_security(*var) }
                sysopen_on_exit(event, retval, *var) { return retval }
              end

              alias_method :foreach_without_security, :foreach

              def foreach(*var)
                retval = nil
                event = foreach_on_enter(*var) { retval = foreach_without_security(*var) }
                foreach_on_exit(event, retval) { return retval }
              end
              
              alias_method :write_without_security, :write
              
              def write(*var, **kwargs)
                retval = nil
                event = write_on_enter(*var, **kwargs) { retval = write_without_security(*var) }
                write_on_exit(event, retval) { return retval }
              end
              
              alias_method :binwrite_without_security, :binwrite
              
              def binwrite(*var)
                retval = nil
                event = binwrite_on_enter(*var) { retval = binwrite_without_security(*var) }
                binwrite_on_exit(event, retval) { return retval }
              end

              alias_method :popen_without_security, :popen
              
              def popen(*var)
                retval = nil
                event = popen_on_enter(*var) { retval = popen_without_security(*var) }
                popen_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end