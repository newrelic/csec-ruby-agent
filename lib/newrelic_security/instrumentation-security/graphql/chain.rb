module NewRelic::Security
  module Instrumentation
    module GraphQL
      module Query
        module Executor
          module Chain
            def self.instrument!
              ::GraphQL::Query::Executor.class_eval do
                class << self
                  include NewRelic::Security::Instrumentation::GraphQL::Query::Executor
    
                  alias_method :execute_without_security, :execute
    
                  def execute
                    execute_on_enter { return execute_without_security }
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
