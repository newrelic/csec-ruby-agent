module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module Mysql2Adapter
          module Chain

            def self.instrument!
              ::ActiveRecord::ConnectionAdapters::Mysql2Adapter.class_eval do
                include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::Mysql2Adapter

                if RUBY_ENGINE == 'jruby'
                  alias_method :execute_without_security, :execute
                
                  def execute(sql, name = nil)
                    retval = nil
                    event = execute_on_enter(sql, name) { retval = execute_without_security(sql, name) }
                    execute_on_exit(event) { return retval }
                  end

                  alias_method :exec_insert_without_security, :exec_insert
                
                  def exec_insert(*var)
                    retval = nil
                    event = exec_insert_on_enter(*var) { retval = exec_insert_without_security(*var) }
                    exec_insert_on_exit(event) { return retval }
                  end

                  alias_method :exec_update_without_security, :exec_update
                
                  def exec_update(*var)
                    retval = nil
                    event = exec_update_on_enter(*var) { retval = exec_update_without_security(*var) }
                    exec_update_on_exit(event) { return retval }
                  end
                  
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

                  alias_method :exec_delete_without_security, :exec_delete

                  def exec_delete(*var)
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
end