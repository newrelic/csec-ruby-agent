module NewRelic::Security
  module Instrumentation
    module Mysql2

      module Client
        module Chain
          def self.instrument!
            ::Mysql2::Client.class_eval do
              include NewRelic::Security::Instrumentation::Mysql2::Client

              alias_method :prepare_without_security, :prepare
    
              def prepare(sql)
                retval = nil
                event = prepare_on_enter(sql) { retval = prepare_without_security(sql) }
                prepare_on_exit(event, retval, sql) { return retval }
              end
              
            end
          end
        end
      end

      module Statement
        module Chain

          def self.instrument!
            ::Mysql2::Statement.class_eval do
              include NewRelic::Security::Instrumentation::Mysql2::Statement

              alias_method :execute_without_security, :execute

              def execute(*args, **kwargs)
                retval = nil
                event = execute_on_enter(*args, **kwargs) { retval = execute_without_security(*args, **kwargs) }
                execute_on_exit(event) { return retval }
              end
              
            end
          end
        end
      end
    end
  end
end