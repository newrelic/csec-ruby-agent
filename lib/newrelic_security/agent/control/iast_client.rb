# frozen_string_literal: true
require 'net/http'
require 'json'
require 'uri'
require 'set'

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
        
        attr_reader :fuzzQ, :iast_dequeue_thread
        attr_accessor :cooldown_till_timestamp, :last_fuzz_cc_timestamp, :pending_request_ids, :completed_requests, :iast_data_transfer_request_processor_thread

        def initialize
          @http = nil
          @fuzzQ = ::SizedQueue.new(FUZZQ_QUEUE_SIZE)
          @cooldown_till_timestamp = current_time_millis
          @last_fuzz_cc_timestamp = current_time_millis
          @pending_request_ids = ::Set.new
          @completed_requests = ::Hash.new
          create_dequeue_threads
          create_iast_data_transfer_request_processor
        end
  
        def enqueue(message)
          @fuzzQ.push(message)
        rescue ThreadError => error
          NewRelic::Security::Agent.logger.error "Exception in event enqueue, #{error.inspect}, Dropping fuzz request"
        end

        private

        def create_dequeue_threads
          # TODO: Create 3 or more consumers for event sending
          @iast_dequeue_thread = Thread.new do
            Thread.current.name = "newrelic_security_iast_thread"
            loop do
              fuzz_request = @fuzzQ.deq #thread blocks when the queue is empty
              fire_request(fuzz_request.id, fuzz_request.request)
              fuzz_request = nil
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event queue creation : #{exception.inspect}"
        end
        
        def create_iast_data_transfer_request_processor
          @iast_data_transfer_request_processor_thread = Thread.new do
            Thread.current.name = "newrelic_security_iast_data_transfer_request_processor"
            loop do
              sleep 1
              current_timestamp = current_time_millis
              cooldown_sleep_time = @cooldown_till_timestamp - current_timestamp
              sleep cooldown_sleep_time/1000 if cooldown_sleep_time > 0
              next if current_timestamp - @last_fuzz_cc_timestamp < 5000
              
              current_fetch_threshold = 300
              remaining_record_capacity = @fuzzQ.max
              current_record_backlog = @fuzzQ.size
              batch_size = current_fetch_threshold - current_record_backlog
              if batch_size > 100 && remaining_record_capacity > batch_size
                iast_data_transfer_request = NewRelic::Security::Agent::Control::IASTDataTransferRequest.new
                iast_data_transfer_request.batchSize = batch_size * 2
                iast_data_transfer_request.pendingRequestIds = pending_request_ids
                iast_data_transfer_request.completedRequests = completed_requests
                NewRelic::Security::Agent.agent.event_processor.send_iast_data_transfer_request(iast_data_transfer_request)
              end
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in create_iast_data_transfer_request_processor creation : #{exception.inspect}"
        end

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def fire_request(fuzz_request_id, request)
          unless @http
            @http = ::Net::HTTP.new('localhost', NewRelic::Security::Agent.config[:listen_port])
            @http.open_timeout = 5
          end
          request[HEADERS].delete(VERSION) if request[HEADERS].key?(VERSION)
          response = @http.send_request(request[METHOD], ::URI.parse(request[URL]).to_s, request[BODY], request[HEADERS])
          NewRelic::Security::Agent.logger.debug "IAST fuzz request : #{request.inspect} \nresponse: #{response.inspect}\n"
        rescue Exception => exception
          NewRelic::Security::Agent.logger.debug "Unable to fire IAST fuzz request : #{exception.inspect} #{exception.backtrace}, sending fuzzfail event for #{request.inspect}\n"
          NewRelic::Security::Agent::Utils.create_fuzz_fail_event(request[HEADERS][NR_CSEC_FUZZ_REQUEST_ID])
        ensure
          NewRelic::Security::Agent.agent.iast_client.pending_request_ids.delete(fuzz_request_id)
        end


      end
    end
  end
end

