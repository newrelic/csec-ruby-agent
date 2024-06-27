# frozen_string_literal: true
require 'net/http'
require 'json'
require 'uri'
require 'set'
require 'resolv'

module NewRelic::Security
  module Agent
    module Control
      FUZZQ_QUEUE_SIZE = 10000
      METHOD = 'method'
      URL = 'url'
      BODY = 'body'
      HEADERS = 'headers'
      VERSION = 'version'
      IS_GRPC = 'isGrpc'
      INPUT_CLASS = 'inputClass'
      SERVER_PORT_1 = 'serverPort'

      class IASTClient
        
        attr_reader :fuzzQ, :iast_dequeue_threads
        attr_accessor :cooldown_till_timestamp, :last_fuzz_cc_timestamp, :pending_request_ids, :completed_requests, :iast_data_transfer_request_processor_thread

        def initialize
          @http = nil
          @stub = nil
          @fuzzQ = ::SizedQueue.new(FUZZQ_QUEUE_SIZE)
          @cooldown_till_timestamp = current_time_millis
          @last_fuzz_cc_timestamp = current_time_millis
          @pending_request_ids = ::Set.new
          @completed_requests = {}
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
          @iast_dequeue_threads = []
          3.times do |t|
            @iast_dequeue_threads << Thread.new do
              Thread.current.name = "newrelic_security_iast_thread-#{t}"
              loop do
                fuzz_request = @fuzzQ.deq #thread blocks when the queue is empty
                if fuzz_request.request[IS_GRPC]
                  fire_grpc_request(fuzz_request.id, fuzz_request.request, fuzz_request.reflected_metadata)
                else
                  fire_request(fuzz_request.id, fuzz_request.request)
                end
                fuzz_request = nil
              end
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
                iast_data_transfer_request.pendingRequestIds = pending_request_ids.to_a
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
          unless ::Thread.current[:http]
            Thread.current[:http] = ::Net::HTTP.new('127.0.0.1', NewRelic::Security::Agent.config[:listen_port])
            Thread.current[:http].open_timeout = 5
            if request[PROTOCOL] == HTTPS
              Thread.current[:http].use_ssl = true
              Thread.current[:http].verify_mode = OpenSSL::SSL::VERIFY_NONE
            end
          end
          request[HEADERS].delete(VERSION) if request[HEADERS].key?(VERSION)
          time_before_request = (Time.now.to_f * 1000).to_i
          response = Thread.current[:http].send_request(request[METHOD], ::URI.parse(request[URL]).to_s, request[BODY], request[HEADERS])
          time_after_request = (Time.now.to_f * 1000).to_i
          NewRelic::Security::Agent.logger.debug "IAST fuzz request : time taken : #{time_after_request - time_before_request}ms, #{request.inspect} \nresponse: #{response.inspect}\n"
        rescue Exception => exception
          NewRelic::Security::Agent.logger.debug "Unable to fire IAST fuzz request Request : #{request.inspect} Exception : #{exception.inspect} #{exception.backtrace}"
        ensure
          NewRelic::Security::Agent.agent.iast_client.completed_requests[fuzz_request_id] = []
          NewRelic::Security::Agent.agent.iast_client.pending_request_ids.delete(fuzz_request_id)
        end

        def fire_grpc_request(fuzz_request_id, request, reflected_metadata)
          service = Object.const_get(request[METHOD].split(SLASH)[0]).superclass
          method = request[METHOD].split(SLASH)[1]
          @stub = service.rpc_stub_class.new("localhost:#{request[SERVER_PORT_1]}", :this_channel_is_insecure) unless @stub
          response = @stub.public_send(method, Object.const_get(reflected_metadata[INPUT_CLASS]).decode_json(request[BODY]), metadata: request[HEADERS])
          # response = @stub.send(method, JSON.parse(request['body'], object_class: OpenStruct))
          # request[HEADERS].delete(VERSION) if request[HEADERS].key?(VERSION)
          NewRelic::Security::Agent.logger.debug "IAST gRPC client response : #{request.inspect} \n#{response.inspect}\n\n\n\n"
        rescue Exception => exception
          NewRelic::Security::Agent.logger.debug "Unable to fire IAST gRPC fuzz request Request : #{request.inspect} Exception : #{exception.inspect} #{exception.backtrace}"
        ensure
          NewRelic::Security::Agent.agent.iast_client.pending_request_ids.delete(fuzz_request_id)
        end

      end
    end
  end
end

