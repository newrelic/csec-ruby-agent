module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module Mysql2Adapter
          module Prepend
            include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::Mysql2Adapter

            def execute(sql, name = nil)
              retval = nil
              event = execute_on_enter(sql, name) { retval = super }
              execute_on_exit(event) { return retval }
            end
            
            if RUBY_ENGINE == 'jruby'
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
end