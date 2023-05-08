module NewRelic::Security
  module Instrumentation
    module Nokogiri
      module XML
        module Node
          module Prepend
            include NewRelic::Security::Instrumentation::Nokogiri::XML

            def xpath(*var)
              retval = nil
              event = xpath_on_enter(*var) { retval = super }
              xpath_on_exit(event) { return retval }
            end
          end
        end

        module NodeSet
          module Prepend
            include NewRelic::Security::Instrumentation::Nokogiri::XML

            def xpath(*var)
              retval = nil
              event = xpath_on_enter(*var) { retval = super }
              xpath_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end