# Event data collector
module NewRelic::Security
    module Agent
      module Control
        module Collector
          def collect(case_type, args, event_category = nil, **keyword_args)
            event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
            $event_list.push(event)
            return false
          end
    
        end
      end
    end
  end