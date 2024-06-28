module NewRelic::Security
  module Instrumentation
    module Elasticsearch
      module Chain

        def self.instrument!
          ::Elastic::Transport::Client.class_eval do
            include NewRelic::Security::Instrumentation::Elasticsearch

            alias_method :perform_request_without_security, :perform_request

            def perform_request(*args)
              retval = nil
              event = perform_request_on_enter(*args) { retval = perform_request_without_security(*args) }
              perform_request_on_exit(event) { return retval }
            end
          end
        end
      end
    end
  end
end