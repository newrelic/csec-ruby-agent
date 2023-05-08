module NewRelic::Security
  module Instrumentation
    module SQLite3
      module Database
        module Prepend
          include NewRelic::Security::Instrumentation::SQLite3::Database
  
          def execute(sql, bind_vars = [], *args, &block)
            retval = nil
            event = execute_on_enter(sql, bind_vars, *args) { retval = super }
            execute_on_exit(event) { return retval }
          end

          def execute2(sql, *bind_vars)
            retval = nil
            event = execute2_on_enter(sql, *bind_vars) { retval = super }
            execute2_on_exit(event) { return retval }
          end

          def execute_batch(sql, bind_vars = [], *args)
            retval = nil
            event = execute_batch_on_enter(sql, bind_vars, *args) { retval = super }
            execute_batch_on_exit(event) { return retval }
          end

          def execute_batch2(sql, &block)
            retval = nil
            event = execute_batch2_on_enter(sql) { retval = super }
            execute_batch2_on_exit(event) { return retval }
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
          include NewRelic::Security::Instrumentation::SQLite3::Statement
          
          def bind_params(*bind_vars)
            retval = nil
            event = bind_params_on_enter(*bind_vars) { retval = super }
            bind_params_on_exit(event) { return retval }
          end

          def execute(*bind_vars)
            retval = nil
            event = execute_on_enter(*bind_vars) { retval = super }
            execute_on_exit(event) { return retval }
          end

        end
      end
    end
  end
end