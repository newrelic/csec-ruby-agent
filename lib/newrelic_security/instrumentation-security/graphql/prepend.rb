module NewRelic::Security
  module Instrumentation
    module GraphQL
      module Query
        module Executor
          module Prepend
            include NewRelic::Security::Instrumentation::GraphQL::Query::Executor

            def execute
              execute_on_enter { return super }
            end

          end
        end
      end
    end
  end
end
