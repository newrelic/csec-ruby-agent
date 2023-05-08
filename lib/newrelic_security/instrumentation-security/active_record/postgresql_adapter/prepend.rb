module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module PostgreSQLAdapter
          module Prepend
            include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::PostgreSQLAdapter
    
            def execute(sql, name = nil)
              retval = nil
              event = execute_on_enter(sql, name) { retval = super }
              execute_on_exit(event) { return retval }
            end

            def exec_query(*var, **key_vars)
              retval = nil
              event = exec_query_on_enter(*var, **key_vars) { retval = super }
              exec_query_on_exit(event) { return retval }
            end

            def exec_update(*var) # Also known as exec_update
              retval = nil
              event = exec_update_on_enter(*var) { retval = super }
              exec_update_on_exit(event) { return retval }
            end

            def exec_delete(*var) # Also known as exec_update
              retval = nil
              event = exec_delete_on_enter(*var) { retval = super }
              exec_delete_on_exit(event) { return retval }
            end
    
          end
        end
      end
    end
  end
end