module NewRelic::Security
  module Instrumentation
    module RandomClass
      module Chain
        def self.instrument!
          ::Random.class_eval do
            include ::NewRelic::Security::Instrumentation::RandomClass

            alias_method :rand_without_security, :rand
  
            def rand(*args)
              retval = nil
              event = rand_on_enter { retval = rand_without_security(*args) }
              rand_on_exit(event) { return retval }
            end

            class << self
              include ::NewRelic::Security::Instrumentation::RandomClass

              alias_method :rand_without_security, :rand
    
              def rand(*args)
                retval = nil
                event = rand_on_enter { retval = rand_without_security(*args) }
                rand_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end