module NewRelic::Security
  module Instrumentation
    module Elasticsearch
      module Prepend
        include NewRelic::Security::Instrumentation::Elasticsearch

        def perform_request(*args)
          retval = nil
          event = perform_request_on_enter(*args) { retval = super }
          perform_request_on_exit(event) { return retval }
        end

      end
    end
  end
end