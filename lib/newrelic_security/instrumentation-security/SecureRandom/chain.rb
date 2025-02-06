module NewRelic::Security
  module Instrumentation
    module SecureRandomClass
      module Chain
        def self.instrument!
          ::SecureRandom.class_eval do
            class << self
              include ::NewRelic::Security::Instrumentation::SecureRandomClass

              alias_method :gen_random_without_security, :gen_random
    
              def gen_random(*args)
                retval = nil
                event = gen_random_on_enter { retval = gen_random_without_security(*args) }
                gen_random_on_exit(event) { return retval }
              end
            end
          end
        end
      end
    end
  end
end