# frozen_string_literal: true

require 'json'

module NewRelic::Security
  module Agent
    module Control

      class HTTPResponse

        attr_accessor :statusCode, :headers, :body

        def initialize(status, headers, body)
          @statusCode = status
          @headers = headers
          @body = read_body_to_string(body)
          @contentType = headers[Content_Type]
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json # rubocop:disable Lint/ToJSON
          as_json.to_json
        end

        private

        def read_body_to_string(body)
          response_body = ::String.new
          body.each { |string| response_body << string }
          response_body
        end
      end
    end
  end
end