module NewRelic::Security
  module Instrumentation
    module Nokogiri
      module XML
        module Node
          module Chain
            def self.instrument!
              ::Nokogiri::XML::Node.class_eval do
                include NewRelic::Security::Instrumentation::Nokogiri::XML
    
                alias_method :xpath_without_security, :xpath
    
                def xpath(*var)
                  retval = nil
                  event = xpath_on_enter(*var) { retval = xpath_without_security(*var) }
                  xpath_on_exit(event) { return retval }
                end
              end
            end
          end
        end
      end
    end
    module Nokogiri
      module XML
        module NodeSet
          module Chain
            def self.instrument!
              ::Nokogiri::XML::NodeSet.class_eval do
                include NewRelic::Security::Instrumentation::Nokogiri::XML
    
                alias_method :xpath_without_security, :xpath
    
                def xpath(*var)
                  retval = nil
                  event = xpath_on_enter(*var) { retval = xpath_without_security(*var) }
                  xpath_on_exit(event) { return retval }
                end
              end
            end
          end
        end
      end
    end
  end
end