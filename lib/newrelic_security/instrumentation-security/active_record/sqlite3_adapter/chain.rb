module NewRelic::Security
  module Instrumentation
    module ActiveRecord
      module ConnectionAdapters
        module SQLite3Adapter
          module Chain

            def self.instrument!
              ::ActiveRecord::ConnectionAdapters::SQLite3Adapter.class_eval do
                include NewRelic::Security::Instrumentation::ActiveRecord::ConnectionAdapters::SQLite3Adapter

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
                
              end
            end
            
          end
        end
      end
    end
  end
end