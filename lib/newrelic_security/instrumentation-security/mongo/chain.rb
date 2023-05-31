module NewRelic::Security
  module Instrumentation
    module Mongo
      module Collection
        module Chain
          def self.instrument!
            ::Mongo::Collection.class_eval do
              include NewRelic::Security::Instrumentation::Mongo::Collection
  
              alias_method :find_without_security, :find
    
              def find(filter = nil, options = {})
                retval = nil
                event = find_on_enter(filter, options) { retval = find_without_security(filter, options) }
                find_on_exit(event) { return retval }
              end

              alias_method :insert_one_without_security, :insert_one
    
              def insert_one(document, opts = {})
                retval = nil
                event = insert_one_on_enter(document, opts) { retval = insert_one_without_security(document, opts) }
                insert_one_on_exit(event) { return retval }
              end

              alias_method :insert_many_without_security, :insert_many
    
              def insert_many(documents, options = {})
                retval = nil
                event = insert_many_on_enter(documents, options) { retval = insert_many_without_security(documents, options) }
                insert_many_on_exit(event) { return retval }
              end

              alias_method :update_one_without_security, :update_one
    
              def update_one(filter, update, options = {})
                retval = nil
                event = update_one_on_enter(filter, update, options) { retval = update_one_without_security(filter, update, options) }
                update_one_on_exit(event) { return retval }
              end

              alias_method :update_many_without_security, :update_many
    
              def update_many(filter, update, options = {})
                retval = nil
                event = update_many_on_enter(filter, update, options) { retval = update_many_without_security(filter, update, options) }
                update_many_on_exit(event) { return retval }
              end

              alias_method :delete_one_without_security, :delete_one
    
              def delete_one(filter = nil, options = {})
                retval = nil
                event = delete_one_on_enter(filter, options) { retval = delete_one_without_security(filter, options) }
                delete_one_on_exit(event) { return retval }
              end

              alias_method :delete_many_without_security, :delete_many
    
              def delete_many(filter = nil, options = {})
                retval = nil
                event = delete_many_on_enter(filter, options) { retval = delete_many_without_security(filter, options) }
                delete_many_on_exit(event) { return retval }
              end

            end
          end
        end

        module View
          module Chain
            def self.instrument!
              ::Mongo::Collection::View.class_eval do
                include NewRelic::Security::Instrumentation::Mongo::Collection::View
    
                alias_method :update_one_without_security, :update_one
  
                def update_one(spec, opts = {})
                  retval = nil
                  event = update_one_on_enter(spec, opts) { retval = update_one_without_security(spec, opts) }
                  update_one_on_exit(event) { return retval }
                end

                alias_method :update_many_without_security, :update_many
    
                def update_many(spec, opts = {})
                  retval = nil
                  event = update_many_on_enter(spec, opts) { retval = update_many_without_security(spec, opts) }
                  update_many_on_exit(event) { return retval }
                end

                alias_method :delete_one_without_security, :delete_one
    
                def delete_one(opts = {})
                  retval = nil
                  event = delete_one_on_enter(opts) { retval = delete_one_without_security(opts) }
                  delete_one_on_exit(event) { return retval }
                end

                alias_method :find_one_and_delete_without_security, :find_one_and_delete
    
                def find_one_and_delete(opts = {})
                  retval = nil
                  event = find_one_and_delete_on_enter(opts) { retval = find_one_and_delete_without_security(opts) }
                  find_one_and_delete_on_exit(event) { return retval }
                end

                alias_method :delete_many_without_security, :delete_many
    
                def delete_many(opts = {})
                  retval = nil
                  event = delete_many_on_enter(opts) { retval = delete_many_without_security(opts) }
                  delete_many_on_exit(event) { return retval }
                end

                alias_method :replace_one_without_security, :replace_one
    
                def replace_one(replacement, opts = {})
                  retval = nil
                  event = replace_one_on_enter(replacement, opts) { retval = replace_one_without_security(replacement, opts) }
                  replace_one_on_exit(event) { return retval }
                end

                alias_method :find_one_and_update_without_security, :find_one_and_update
                
                def find_one_and_update(document, opts = {})
                  retval = nil
                  event = find_one_and_update_on_enter(document, opts) { retval = find_one_and_update_without_security(document, opts) }
                  find_one_and_update_on_exit(event) { return retval }
                end
  
              end
            end
          end
        end
      end
    end
  end
end