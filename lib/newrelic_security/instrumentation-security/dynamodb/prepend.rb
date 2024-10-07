module NewRelic::Security
  module Instrumentation
    module Aws
      module DynamoDB
        module Client
          module Prepend
            include NewRelic::Security::Instrumentation::Aws::DynamoDB::Client

            def put_item(*args)
              retval = nil
              event = put_item_on_enter(*args) { retval = super }
              put_item_on_exit(event) { return retval }
            end

            def get_item(*args)
              retval = nil
              event = get_item_on_enter(*args) { retval = super }
              get_item_on_exit(event) { return retval }
            end

            def update_item(*args)
              retval = nil
              event = update_item_on_enter(*args) { retval = super }
              update_item_on_exit(event) { return retval }
            end

            def delete_item(*args)
              retval = nil
              event = delete_item_on_enter(*args) { retval = super }
              delete_item_on_exit(event) { return retval }
            end

          end
        end
      end

    end
  end
end
