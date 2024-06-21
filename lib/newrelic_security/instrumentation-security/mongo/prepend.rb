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
        end

        module View
          module Prepend
            include NewRelic::Security::Instrumentation::Mongo::Collection::View

            def update_one(spec, opts = {})
              retval = nil
              event = update_one_on_enter(spec, opts) { retval = super }
              update_one_on_exit(event) { return retval }
            end

            def update_many(spec, opts = {})
              retval = nil
              event = update_many_on_enter(spec, opts) { retval = super }
              update_many_on_exit(event) { return retval }
            end

            def delete_one(opts = {})
              retval = nil
              event = delete_one_on_enter(opts) { retval = super }
              delete_one_on_exit(event) { return retval }
            end

            def find_one_and_delete(opts = {})
              retval = nil
              event = find_one_and_delete_on_enter(opts) { retval = super }
              find_one_and_delete_on_exit(event) { return retval }
            end

            def delete_many(opts = {})
              retval = nil
              event = delete_many_on_enter(opts) { retval = super }
              delete_many_on_exit(event) { return retval }
            end

            def replace_one(replacement, opts = {})
              retval = nil
              event = replace_one_on_enter(replacement, opts) { retval = super }
              replace_one_on_exit(event) { return retval }
            end
            
            def find_one_and_update(document, opts = {})
              retval = nil
              event = find_one_and_update_on_enter(document, opts) { retval = super }
              find_one_and_update_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end