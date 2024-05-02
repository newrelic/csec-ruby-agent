module NewRelic::Security
  module Instrumentation
    module SQLite3
      module Database
        module Chain

          def self.instrument!
            ::SQLite3::Database.class_eval do
              include NewRelic::Security::Instrumentation::SQLite3::Database

              alias_method :execute_without_security, :execute

              def execute(sql, bind_vars = [], *args, &block)
                retval = nil
                event = execute_on_enter(sql, bind_vars, *args) { retval = execute_without_security(sql, bind_vars, *args, &block) }
                execute_on_exit(event) { return retval }
              end

              alias_method :execute_batch_without_security, :execute_batch
    
              def execute_batch(sql, bind_vars = [], *args)
                retval = nil
                event = execute_batch_on_enter(sql, bind_vars, *args) { retval = execute_batch_without_security(sql, bind_vars, *args) }
                execute_batch_on_exit(event) { return retval }
              end

              alias_method :execute_batch2_without_security, :execute_batch2
    
              def execute_batch2(sql, &block)
                retval = nil
                event = execute_batch2_on_enter(sql) { retval = execute_batch2_without_security(sql, &block) }
                execute_batch2_on_exit(event) { return retval }
              end
              
            end
          end
        end
      end

      module Statement
        module Chain

          def self.instrument!
            ::SQLite3::Statement.class_eval do
              include NewRelic::Security::Instrumentation::SQLite3::Statement

              alias_method :initialize_without_security, :initialize
    
              def initialize(db, sql)
                retval = nil
                event = initialize_on_enter(db, sql) { retval = initialize_without_security(db, sql) }
                initialize_on_exit(event, retval, sql) { return retval }
              end

              alias_method :bind_params_without_security, :bind_params

              def bind_params(*bind_vars)
                retval = nil
                event = bind_params_on_enter(*bind_vars) { retval = bind_params_without_security(*bind_vars) }
                bind_params_on_exit(event) { return retval }
              end

              alias_method :execute_without_security, :execute

              def execute(*bind_vars)
                retval = nil
                event = execute_on_enter(*bind_vars) { retval = execute_without_security(*bind_vars) }
                execute_on_exit(event) { return retval }
              end
              
            end
          end
        end
      end
    end
  end
end