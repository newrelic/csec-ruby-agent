module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module PostgreSQLAdapter
          module Prepend
            include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::PostgreSQLAdapter

            if ::Rails.version < '5'
              def exec_query(*var)
                retval = nil
                event = exec_query_on_enter(*var) { retval = super }
                exec_query_on_exit(event) { return retval }
              end
            else
              def exec_query(*var, **key_vars)
                retval = nil
                event = exec_query_on_enter(*var, **key_vars) { retval = super }
                exec_query_on_exit(event) { return retval }
              end
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