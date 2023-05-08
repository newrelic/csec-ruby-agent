module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module SQLite3Adapter
          module Prepend
            include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::SQLite3Adapter
    
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