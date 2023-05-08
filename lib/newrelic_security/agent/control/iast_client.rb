# frozen_string_literal: true
require 'net/http'
require 'json'
require 'uri'

module NewRelic::Security
  module Agent
    module Control
      FUZZQ_QUEUE_SIZE = 10000
      METHOD = 'method'
      URL = 'url'
      BODY = 'body'
      HEADERS = 'headers'
      VERSION = 'version'

      class IASTClient
        
        attr_reader :fuzzQ

        def initialize
          @http = nil
          @fuzzQ = ::SizedQueue.new(EVENT_QUEUE_SIZE)
          create_dequeue_threads
        end
  
        def enqueue(message)
          @fuzzQ.push(message)
        rescue ThreadError => error
          NewRelic::Security::Agent.logger.error "Exception in event enqueue, #{error.inspect}, Dropping fuzz request"
        end

        private

        def create_dequeue_threads
          # TODO: Create 3 or more consumers for event sending
          Thread.new do
            loop do
              fuzz_request = @fuzzQ.deq #thread blocks when the queue is empty
              process_fuzz_request(fuzz_request[0])
              fuzz_request = nil
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event queue creation : #{exception.inspect}"
        end

        def process_fuzz_request(fuzz_request)
          fuzz_request.gsub!(NR_CSEC_VALIDATOR_HOME_TMP, NR_SECURITY_HOME_TMP)
          prepared_fuzz_request = ::JSON.parse(fuzz_request)
          fire_request(prepared_fuzz_request)
          prepared_fuzz_request = nil
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in processing fuzz request : #{exception.inspect} #{exception.backtrace}"
        end

        def fire_request(request)
          @http = ::Net::HTTP.new('localhost', NewRelic::Security::Agent.config[:listen_port]) unless @http
          request[HEADERS].delete(VERSION) if request[HEADERS].key?(VERSION)
          response = @http.send_request(request[METHOD], ::URI.parse(request[URL]).to_s, request[BODY], request[HEADERS])
          NewRelic::Security::Agent.logger.debug "IAST client response : #{request.inspect} \n#{response.inspect}\n\n\n\n"
        rescue Exception => exception
          NewRelic::Security::Agent.logger.debug "Unable to fire IAST fuzz request : #{exception.inspect} #{exception.backtrace}, sending fuzzfail event"
          NewRelic::Security::Agent::Utils.create_fuzz_fail_event(request[HEADERS][NR_CSEC_FUZZ_REQUEST_ID])
        end


      end
    end
  end
end

