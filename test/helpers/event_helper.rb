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
        
        def get_event_count(caseType)
          event_count = 0
          for event in $event_list
            event_count += 1 if event.caseType == caseType
          end
          return event_count
        end
      end
    end
  end
end