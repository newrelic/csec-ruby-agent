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
      IS_GRPC = 'isGrpc'
      INPUT_CLASS = 'inputClass'
      SERVER_PORT_1 = 'serverPort'

      class IASTClient
        
        attr_reader :fuzzQ, :iast_dequeue_thread

        def initialize
          @http = nil
          @stub = nil
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
          @iast_dequeue_thread = Thread.new do
            Thread.current.name = "newrelic_security_iast_thread"
            loop do
              message_object = @fuzzQ.deq #thread blocks when the queue is empty
              process_fuzz_request(message_object)
              message_object = nil
            end
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in event queue creation : #{exception.inspect}"
        end

        def process_fuzz_request(message_object)
          message_object[:arguments][0].gsub!(NR_CSEC_VALIDATOR_HOME_TMP, NR_SECURITY_HOME_TMP)
          message_object[:arguments][0].gsub!(NR_CSEC_VALIDATOR_FILE_SEPARATOR, ::File::SEPARATOR)
          prepared_fuzz_request = ::JSON.parse(message_object[:arguments][0])
          if prepared_fuzz_request[IS_GRPC]
            fire_grpc_request(prepared_fuzz_request, message_object[:reflectedMetaData])
          else
            fire_request(prepared_fuzz_request)
          end
          prepared_fuzz_request = nil
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in processing fuzz request : #{exception.inspect} #{exception.backtrace}"
        end

        def fire_request(request)
          unless @http
            @http = ::Net::HTTP.new('localhost', NewRelic::Security::Agent.config[:listen_port])
            @http.open_timeout = 5
          end
          request[HEADERS].delete(VERSION) if request[HEADERS].key?(VERSION)
          response = @http.send_request(request[METHOD], ::URI.parse(request[URL]).to_s, request[BODY], request[HEADERS])
          NewRelic::Security::Agent.logger.debug "IAST client response : #{request.inspect} \n#{response.inspect}\n\n\n\n"
        rescue Exception => exception
          NewRelic::Security::Agent.logger.debug "Unable to fire IAST fuzz request : #{exception.inspect} #{exception.backtrace}, sending fuzzfail event"
          NewRelic::Security::Agent::Utils.create_fuzz_fail_event(request[HEADERS][NR_CSEC_FUZZ_REQUEST_ID])
        end

        def fire_grpc_request(request, reflected_metadata)
          service = Object.const_get(request[METHOD].split(SLASH)[0]).superclass
          method = request[METHOD].split(SLASH)[1]
          @stub = service.rpc_stub_class.new("localhost:#{request[SERVER_PORT_1]}", :this_channel_is_insecure) unless @stub
          response = @stub.public_send(method, Object.const_get(reflected_metadata[INPUT_CLASS]).decode_json(request[BODY]))
          # response = @stub.send(method, JSON.parse(request['body'], object_class: OpenStruct))
          # request[HEADERS].delete(VERSION) if request[HEADERS].key?(VERSION)
          NewRelic::Security::Agent.logger.debug "IAST gRPC client response : #{request.inspect} \n#{response.inspect}\n\n\n\n"
        rescue Exception => exception
          NewRelic::Security::Agent.logger.debug "Unable to fire IAST gRPC fuzz request : #{exception.inspect} #{exception.backtrace}, sending fuzzfail event"
          NewRelic::Security::Agent::Utils.create_fuzz_fail_event(request[HEADERS][NR_CSEC_FUZZ_REQUEST_ID])
        end


      end
    end
  end
end

