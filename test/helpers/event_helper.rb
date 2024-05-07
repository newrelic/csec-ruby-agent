# Event data collector
module NewRelic::Security
  module Agent
    module Control
      module Collector
        def collect(case_type, args, event_category = nil, **keyword_args)
          event = NewRelic::Security::Agent::Control::Event.new(case_type, args, event_category)
          $event_list.push(event)
          false
        end
        
        def get_event_count(caseType)
          filter_events(caseType)
          $event_list.size
        end

        def filter_events(caseType)
          $event_list.reject! { |event| event if event.caseType != caseType }
        end
      end
    end
  end
end