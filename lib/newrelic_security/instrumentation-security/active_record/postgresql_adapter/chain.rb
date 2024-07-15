module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module PostgreSQLAdapter
          module Chain

            def self.instrument!
              ::ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.class_eval do
                include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::PostgreSQLAdapter

                alias_method :exec_query_without_security, :exec_query

                if ::Rails.version < '5'
                  def exec_query(*var)
                    retval = nil
                    event = exec_query_on_enter(*var) { retval = exec_query_without_security(*var) }
                    exec_query_on_exit(event) { return retval }
                  end
                else
                  def exec_query(*var, **key_vars)
                    retval = nil
                    event = exec_query_on_enter(*var, **key_vars) { retval = exec_query_without_security(*var, **key_vars) }
                    exec_query_on_exit(event) { return retval }
                  end
                end

                alias_method :exec_update_without_security, :exec_update
    
                def exec_update(*var) # Also known as exec_update
                  retval = nil
                  event = exec_update_on_enter(*var) { retval = exec_update_without_security(*var) }
                  exec_update_on_exit(event) { return retval }
                end

                alias_method :exec_delete_without_security, :exec_delete
    
                def exec_delete(*var) # Also known as exec_update
                  retval = nil
                  event = exec_delete_on_enter(*var) { retval = exec_delete_without_security(*var) }
                  exec_delete_on_exit(event) { return retval }
                end
              end
            end
          end
        end
      end
    end
  end
end