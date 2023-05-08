module NewRelic::Security
  module Instrumentation
    module Mysql2
      module Client
        module Prepend
          include NewRelic::Security::Instrumentation::Mysql2::Client
  
          def query(sql, options = {})
            retval = nil
            event = query_on_enter(sql, options) { retval = super }
            query_on_exit(event) { return retval }
          end

          def prepare(sql)
            retval = nil
            event = prepare_on_enter(sql) { retval = super }
            prepare_on_exit(event, retval, sql) { return retval }
          end

        end
      end

      module Statement
        module Prepend
          include NewRelic::Security::Instrumentation::Mysql2::Statement
          
          def execute(*args, **kwargs)
            retval = nil
            event = execute_on_enter(*args, **kwargs) { retval = super }
            execute_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end