module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module SQLite3Adapter
          module Prepend
            include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::SQLite3Adapter

            if RUBY_ENGINE == 'jruby'
              def execute(sql, name = nil)
                retval = nil
                event = execute_on_enter(sql, name) { retval = super }
                execute_on_exit(event) { return retval }
              end

              def exec_update(*var)
                retval = nil
                event = exec_update_on_enter(*var) { retval = super }
                exec_update_on_exit(event) { return retval }
              end

              def exec_delete(*var)
                retval = nil
                event = exec_delete_on_enter(*var) { retval = super }
                exec_delete_on_exit(event) { return retval }
              end
            end

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
    
          end
        end
      end
    end
  end
end