module NewRelic::Security
  module Instrumentation
    module Mongo
      module Collection
        module Prepend
          include NewRelic::Security::Instrumentation::Mongo::Collection
  
          def find(filter = nil, options = {})
            retval = nil
            event = find_on_enter(filter, options) { retval = super }
            find_on_exit(event) { return retval }
          end

          def insert_one(document, opts = {})
            retval = nil
            event = insert_one_on_enter(document, opts) { retval = super }
            insert_one_on_exit(event) { return retval }
          end

          def insert_many(documents, options = {})
            retval = nil
            event = insert_many_on_enter(documents, options) { retval = super }
            insert_many_on_exit(event) { return retval }
          end

          def update_one(filter, update, options = {})
            retval = nil
            event = update_one_on_enter(filter, update, options) { retval = super }
            update_one_on_exit(event) { return retval }
          end

          def update_many(filter, update, options = {})
            retval = nil
            event = update_many_on_enter(filter, update, options) { retval = super }
            update_many_on_exit(event) { return retval }
          end

          def delete_one(filter = nil, options = {})
            retval = nil
            event = delete_one_on_enter(filter, options) { retval = super }
            delete_one_on_exit(event) { return retval }
          end

          def delete_many(filter = nil, options = {})
            retval = nil
            event = delete_many_on_enter(filter, options) { retval = super }
            delete_many_on_exit(event) { return retval }
          end
  
        end
      end
    end
  end
end