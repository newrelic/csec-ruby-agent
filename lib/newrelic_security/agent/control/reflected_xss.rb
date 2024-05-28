# frozen_string_literal: true
require 'set'
require 'cgi'
require 'json'

module NewRelic::Security
  module Agent
    module Control
      module ReflectedXSS

        LESS_THAN = '<'
        GREATER_THAN = '>'
        EQUAL = '='
        HTML_COMMENT_START = '!--'
        HTML_COMMENT_END = '-->'
        FIVE_COLON = ':::::'
        SCRIPT = 'script'
        Content_Type = 'Content-Type'
        QUERY_STRING = 'QUERY_STRING'
        REQUEST_URI = 'REQUEST_URI'
        APPLICATION_JSON = 'application/json'
        APPLICATION_XML = 'application/xml'
        APPLICATION_X_WWW_FORM_URLENCODED = 'application/x-www-form-urlencoded'
        ON1 = 'on'
        ON2 = 'ON'
        ON3 = 'On'
        ON4 = 'oN'
        SRC ='src'
        HREF = 'href'
        ACTION = 'action'
        FORMACTION = 'formaction'
        SRCDOC = 'srcdoc'
        DATA = 'data'

        TAG_NAME_REGEX = ::Regexp.new("<([a-zA-Z_\\-]+[0-9]*|!--)", ::Regexp::MULTILINE | ::Regexp::IGNORECASE )
        ATTRIBUTE_REGEX = ::Regexp.new("([^(\\/\\s<'\">)]+?)(?:\\s*)=\\s*(('|\")([\\s\\S]*?)(?:(?=(\\\\?))\\5.)*?\\3|.+?(?=\\/>|>|\\?>|\\s|<\\/|$))", Regexp::MULTILINE | Regexp::IGNORECASE)
        UNSUPPORTED_MEDIA_TYPES = %w[video/ image/ font/ audio/].freeze
        UNSUPPORTED_CONTENT_TYPES = %w[application/zip application/epub+zip application/gzip application/java-archive application/msword application/octet-stream application/ogg application/pdf application/rtf application/vnd.amazon.ebook application/vnd.apple.installer+xml application/vnd.ms-excel application/vnd.ms-fontobject 
                                       application/vnd.ms-powerpoint application/vnd.oasis.opendocument.presentation application/vnd.oasis.opendocument.spreadsheet application/vnd.oasis.opendocument.text application/vnd.openxmlformats-officedocument.presentationml.presentation 
                                       application/vnd.openxmlformats-officedocument.spreadsheetml.sheet application/vnd.openxmlformats-officedocument.wordprocessingml.document application/vnd.rar application/vnd.visio application/x-7z-compressed application/x-abiword application/x-bzip application/x-bzip2 application/x-cdf 
                                       application/x-freearc application/x-tar application/zip text/calendar ].freeze
  

        extend self

        def check_xss(http_req, retval)
          # TODO: Check if enableHTTPRequestPrinting is required.
          return if http_req.nil? || retval.empty?
          if retval[1].key?(Content_Type) && (retval[1][Content_Type].start_with?(*UNSUPPORTED_MEDIA_TYPES) || retval[1][Content_Type].start_with?(*UNSUPPORTED_CONTENT_TYPES))
            return
          end
          response_body = ::String.new
          retval[2].each { |string| response_body << string }
          construct = check_for_reflected_xss(http_req, retval[1], response_body)
          NewRelic::Security::Agent.logger.debug "RXSS Attack DATA: #{construct}"
          if !construct.empty? || NewRelic::Security::Agent::Utils.is_IAST?
            parameters = Array.new
            parameters << construct
            parameters << response_body.force_encoding(ISO_8859_1).encode(UTF_8)
            NewRelic::Security::Agent::Control::Collector.collect(REFLECTED_XSS, parameters, nil, :response_header => retval[1][Content_Type])
          end
        rescue Exception => exception
          NewRelic::Security::Agent.logger.error "Exception in Reflected XSS detection : #{exception.inspect} #{exception.backtrace}"
        end

        private

        def check_for_reflected_xss(http_req, headers, response_body)
          final_attack_construct = ::String.new
          to_return = ::String.new
          combined_request_data = decode_request_data(http_req)
          combined_response_data = decode_response_data(headers, response_body)
          combined_response_data_string = combined_response_data.to_a.join(FIVE_COLON)
          attack_constructs  = is_xss(combined_request_data)
          NewRelic::Security::Agent.logger.debug "RXSS attack_constructs ==> #{attack_constructs}"
          attack_constructs.each { |construct| to_return = construct if combined_response_data_string.include?(construct) }
          if !to_return.empty?
            response_constructs = is_xss(combined_response_data)
            response_constructs.each { |construct| final_attack_construct = to_return if construct.include?(to_return) }
          end
          combined_request_data = nil
          combined_response_data = nil
          combined_response_data_string = nil
          final_attack_construct
        end

        def decode_request_data(http_req)
          processed_data = ::Set.new
          content_type = http_req.req[CONTENT_TYPE]
          body = http_req.body
          http_req.req.each do | key, value |
            process_url_encoded_data_for_xss(processed_data, key)
            process_url_encoded_data_for_xss(processed_data, value)
          end          
          if http_req.params != nil 
            items = ::Set.new
            get_key_values(http_req.params, items)
            items.each { |item| processed_data.add(item) if item.include?(LESS_THAN) }
          end
          process_url_encoded_data_for_xss(processed_data, http_req.req[REQUEST_URI])
          processed_data.add(body) unless body.nil? || body.empty?
          if body != nil && !body.empty?
            case content_type
            when APPLICATION_JSON
              oldBody = body.dup
              body = ::JSON.parse(body)
              if oldBody != body && body.include?(LESS_THAN)
                processed_data.add(body)
              end
            when APPLICATION_XML
              # Unescaping of xml data is remaining
              processed_data.add(body)
            when APPLICATION_X_WWW_FORM_URLENCODED
              body = ::CGI.unescape(body, encoding = UTF_8)
              processed_data.add(body)
              oldBody = body
              body = ::CGI.unescape(body, encoding = UTF_8)
              processed_data.add(body) if oldBody != body && body.include?(LESS_THAN)
            end
          end
          processed_data
        end

        def decode_response_data(headers, response_body)
          processed_data = ::Set.new
          content_type = headers[Content_Type]
          response_body = response_body
          processed_body = response_body.force_encoding(UTF_8)
          processed_data.add(processed_body)
          old_processed_body = String.new
          if response_body != nil && !response_body.empty?
            case content_type
            when APPLICATION_JSON
              # do while loop in java code here
              old_processed_body = processed_body
              body = ::JSON.parse(processed_body)
              processed_data.add(body) if old_processed_body != body && body.to_s.include?(LESS_THAN)
            when APPLICATION_XML
              # Unescaping of xml data is remaining
              processed_data.add(processed_data)
            end
          end
          processed_data
        end

        def is_xss(combined_data)
          attack_constructs = ::Set.new
          for data in combined_data do
            constructs = get_xss_constructs(data)
            constructs.each { |str| attack_constructs.add(str) }
          end
          return attack_constructs
        end

        def process_url_encoded_data_for_xss(processed_data, data)
          processed_data.add(data) if data && data.include?(LESS_THAN)
          decoded_uri = ::CGI.unescape(data, encoding = UTF_8) if data
          processed_data.add(decoded_uri) if decoded_uri && decoded_uri.include?(LESS_THAN)
        end

        def get_key_values(hash, items)
          hash.each do |k,v|
            items.add(k.to_s)
            if v.instance_of?(Hash)
              get_key_values(v, items)
            else
              items.add(v.to_s) unless v.nil?
            end
          end
        end

        def get_xss_constructs(data)
          constructs = ::Set.new
          is_attack_construct = false
          curr_pos = 0
          start_pos = 0
          tmp_curr_pos = 0
          tmp_start_pos = 0
      
          while curr_pos < data.length
            matcher = TAG_NAME_REGEX.match(data, curr_pos)
            is_attack_construct = false
            return constructs if matcher.nil?
            tagName = matcher[1]
            return constructs if tagName.empty?
            start_pos = matcher.begin(0)
            curr_pos = matcher.end(0) - 1
            if tagName == HTML_COMMENT_START
              tmp_curr_pos = start_pos + data.index(HTML_COMMENT_END, start_pos)
              if tmp_curr_pos == nil
                break
              else
                curr_pos = tmp_curr_pos
                next
              end
            end
            tmp_start_pos = tmp_curr_pos = data.index(GREATER_THAN, start_pos)
            tmp_start_pos = start_pos if tmp_curr_pos.nil?
            while ATTRIBUTE_REGEX.match?(data, curr_pos)
              attribute_matcher = ATTRIBUTE_REGEX.match(data, curr_pos)
              attribute_data = attribute_matcher[0]
              curr_pos = attribute_matcher.end(0) - 1
              tmp_curr_pos = data.index(GREATER_THAN, tmp_start_pos ? tmp_start_pos : -1)          
              if tmp_curr_pos == nil || attribute_matcher.begin(0) < tmp_curr_pos
                tmp_start_pos = tmp_curr_pos = attribute_matcher.end(0) - 1
                tmp_start_pos += 1
                if (attribute_matcher[3] == nil || attribute_matcher[3] == EMPTY_STRING) && attribute_matcher.end(0) > tmp_curr_pos
                  tmp_start_pos = tmp_curr_pos = data.index(GREATER_THAN, attribute_matcher.begin(0)) ? data.index(GREATER_THAN, attribute_matcher.begin(0)) : -1
                  attribute_data = attribute_data[0..tmp_start_pos]
                end
                key = attribute_data[0..attribute_data.index(EQUAL) - 1]
                val = attribute_data[attribute_data.index(EQUAL) + 1.. attribute_data.length]              
                if key != nil && key != EMPTY_STRING && key.start_with?(ON1, ON2, ON3, ON4) || key.casecmp?(SRC) || key.casecmp?(HREF) || key.casecmp?(ACTION) || key.casecmp?(FORMACTION) || key.casecmp?(SRCDOC) || key.casecmp?(DATA) || ::CGI.unescapeHTML(val).gsub(/[[:space:]]/, EMPTY_STRING).match?(/javascript:/i)
                  is_attack_construct = true
                end
              else
                break
              end
            end
            if tmp_curr_pos != nil && tmp_curr_pos > 0
              curr_pos = tmp_curr_pos
            end
            if data[curr_pos] != GREATER_THAN
              tmp = data.index(GREATER_THAN, curr_pos)
              if tmp != nil
                curr_pos = tmp
              elsif !is_attack_construct
                next
              end
            end
        
            if tagName.strip.casecmp?(SCRIPT)
              location_of_end_tag = data.index(/<\/script/i, curr_pos)
              if location_of_end_tag != nil
                body = data[curr_pos + 1..location_of_end_tag-1]
                if body != nil && body != EMPTY_STRING
                  constructs.add(data[start_pos..curr_pos] + body)
                  next
                end
              else
                body = data[curr_pos + 1 ..  data.length]
                tag_end = body.index(GREATER_THAN)
                if body != nil && body != EMPTY_STRING && tag_end != nil
                  body = body[tag_end..data.length]
                  constructs.add(data[start_pos..curr_pos] + body)
                  break
                end
              end
            end
          constructs.add(data[start_pos..curr_pos]) if is_attack_construct
          end
          constructs
        end

      end
    end
  end
end