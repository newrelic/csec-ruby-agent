module NewRelic::Security
  module Instrumentation
    module NetLDAP
      module Chain
        def self.instrument!
          ::Net::LDAP.class_eval do
            include NewRelic::Security::Instrumentation::NetLDAP

            alias_method :search_without_security, :search
  
            def search(args = {}, &block)
              retval = nil
              event = search_on_enter(args) { retval = search_without_security(args, &block) }
              search_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end