module NewRelic::Security
  module Instrumentation
    module PG
      module Connection
        module Chain

          def self.instrument!
            ::PG::Connection.class_eval do
              include NewRelic::Security::Instrumentation::PG::Connection

              alias_method :exec_without_security, :exec

              def exec(sql)
                retval = nil
                event = exec_on_enter(sql) { retval = exec_without_security(sql) }
                exec_on_exit(event) { return retval }
              end

              alias_method :async_exec_without_security, :async_exec

              def async_exec(*args)
                retval = nil
                event = async_exec_on_enter(*args) { retval = async_exec_without_security(*args) }
                async_exec_on_exit(event) { return retval }
              end
              
              alias_method :prepare_without_security, :prepare

              def prepare(*args)
                retval = nil
                event = prepare_on_enter(*args) { retval = prepare_without_security(*args) }
                prepare_on_exit(event) { return retval }
              end

              alias_method :exec_prepared_without_security, :exec_prepared

              def exec_prepared(*args)
                retval = nil
                event = exec_prepared_on_enter(*args) { retval = exec_prepared_without_security(*args) }
                exec_prepared_on_exit(event) { return retval }
              end

            end
          end
        end
      end
    end
  end
end