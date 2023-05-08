module NewRelic::Security
  module Instrumentation
    module PG
      module Connection
        module Prepend
          include NewRelic::Security::Instrumentation::PG::Connection
  
          def exec(sql)
            retval = nil
            event = exec_on_enter(sql) { retval = super }
            exec_on_exit(event) { return retval }
          end

          def prepare(*args)
            retval = nil
            event = prepare_on_enter(*args) { retval = super }
            prepare_on_exit(event) { return retval }
          end

          def exec_prepared(*args)
            retval = nil
            event = exec_prepared_on_enter(*args) { retval = super }
            exec_prepared_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end