module NewRelic::Security
  module Instrumentation
    module Aws
      module DynamoDB
        module Client
          module Chain

            def self.instrument!
              ::Aws::DynamoDB::Client.class_eval do
                include NewRelic::Security::Instrumentation::Aws::DynamoDB::Client
  
                alias_method :put_item_without_security, :put_item
  
                def put_item(*args)
                  retval = nil
                  event = put_item_on_enter(*args) { retval = put_item_without_security(*args) }
                  put_item_on_exit(event) { return retval }
                end

                alias_method :get_item_without_security, :get_item
  
                def get_item(*args)
                  retval = nil
                  event = get_item_on_enter(*args) { retval = get_item_without_security(*args) }
                  get_item_on_exit(event) { return retval }
                end

                alias_method :update_item_without_security, :update_item
  
                def update_item(*args)
                  retval = nil
                  event = update_item_on_enter(*args) { retval = update_item_without_security(*args) }
                  update_item_on_exit(event) { return retval }
                end

                alias_method :delete_item_without_security, :delete_item
  
                def delete_item(*args)
                  retval = nil
                  event = delete_item_on_enter(*args) { retval = delete_item_without_security(*args) }
                  delete_item_on_exit(event) { return retval }
                end
                
              end
            end
          end
        end
      end

    end
  end
end