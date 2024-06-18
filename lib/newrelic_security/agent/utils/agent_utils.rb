# frozen_string_literal: true
require 'fileutils'
require 'socket'
require 'openssl'

module NewRelic::Security
  module Agent
    module Utils
      extend self

      VULNERABILITY_SCAN = 'vulnerabilityScan'
      ENABLED = 'enabled'
      IAST_SCAN = 'iastScan'
      VULNERABLE = 'VULNERABLE'
      AES_256_CBC = 'AES-256-CBC'
      H_ASTERIK = 'H*'
      ASTERISK = '*'

      def is_IAST?
        return false if NewRelic::Security::Agent.config[:policy].empty?
        return NewRelic::Security::Agent.config[:policy][VULNERABILITY_SCAN][IAST_SCAN][ENABLED] if NewRelic::Security::Agent.config[:policy][VULNERABILITY_SCAN][ENABLED]
        false
      end

      def is_IAST_request?(headers)
        return true if headers&.key?(NR_CSEC_FUZZ_REQUEST_ID)
        false
      end

      def parse_fuzz_header
        headers = NewRelic::Security::Agent::Control::HTTPContext.get_context.headers
        if is_IAST? && is_IAST_request?(headers)
          fuzz_request = headers[NR_CSEC_FUZZ_REQUEST_ID].split(COLON_IAST_COLON)
          if fuzz_request.length() >= 7
            decrypted_data = decrypt_data(fuzz_request[6], fuzz_request[7]) if fuzz_request[6] && fuzz_request[7] && !fuzz_request[6].empty? && !fuzz_request[7].empty?
            if decrypted_data
              NewRelic::Security::Agent.logger.debug "Encrypted data: #{fuzz_request[6]},  decrypted data: #{decrypted_data}, Sha256: #{fuzz_request[7]}"
              decrypted_data.split(COMMA).each do |filename|
                begin
                  filename.gsub!(NR_CSEC_VALIDATOR_HOME_TMP, NewRelic::Security::Agent.config[:fuzz_dir_path])
                  filename.gsub!(NR_CSEC_VALIDATOR_FILE_SEPARATOR, ::File::SEPARATOR)
                  dirname = ::File.dirname(filename)
                  ::FileUtils.mkdir_p(dirname, :mode => 0770) unless ::File.directory?(dirname)
                  NewRelic::Security::Agent::Control::HTTPContext.get_context&.fuzz_files << filename
                  ::File.open(filename, ::File::WRONLY | ::File::CREAT | ::File::EXCL) do |fd|
                      # puts "Ownership acquired by : #{Process.pid}"
                  end unless ::File.exist?(filename)
                rescue
                end
              end
            end
          end
        end
      end

      def decrypt_data(name, sha)
        cipher = ::OpenSSL::Cipher.new AES_256_CBC
        cipher.decrypt
        cipher.key = NewRelic::Security::Agent.config[:extraction_key]
        decrypted = cipher.update [name].pack(H_ASTERIK)
        decrypted << cipher.final
        fname = decrypted[16..-1]
        return fname if ::Digest::SHA256.hexdigest(fname) == sha
        nil
      rescue Exception => exception
        NewRelic::Security::Agent.logger.error "Exception in decrypt_data: #{exception.inspect} #{exception.backtrace}"
      end

      def delete_created_files
        return unless NewRelic::Security::Agent::Control::HTTPContext.get_context
        headers = NewRelic::Security::Agent::Control::HTTPContext.get_context.headers
        if is_IAST? && is_IAST_request?(headers)
          NewRelic::Security::Agent::Control::HTTPContext.get_context.fuzz_files.each do |file|
            begin
              ::File.delete(file)
            rescue
            end
          end
        end
      end

      def create_exit_event(event)
        return unless event
        return unless is_IAST?
        return unless is_IAST_request?(event.httpRequest[:headers])
        if event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID].include?(event.apiId) && event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID].include?(VULNERABLE)
          exit_event = NewRelic::Security::Agent::Control::ExitEvent.new
          exit_event.executionId = event.id
          exit_event.caseType = event.caseType
          exit_event.k2RequestIdentifier = event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID]
          NewRelic::Security::Agent.agent.event_processor.send_exit_event(exit_event)
        end
      rescue Exception => exception
        NewRelic::Security::Agent.logger.error "Exception in create_exit_event: #{exception.inspect} #{exception.backtrace}"
        NewRelic::Security::Agent.agent.exit_event_stats.error_count.increment
      end

      def get_app_routes(framework, router = nil)
        enable_object_space_in_jruby
        if framework == :rails
          ::Rails.application.routes.routes.each do |route|
            if route.verb.is_a?(::Regexp)
              method = route.verb.inspect.match(/[a-zA-Z]+/)
              NewRelic::Security::Agent.agent.route_map << "#{method}@#{route.path.spec.to_s.gsub(/\(\.:format\)/, "")}" if method
            else
              route.verb.split("|").each { |method|
                NewRelic::Security::Agent.agent.route_map << "#{method}@#{route.path.spec.to_s.gsub(/\(\.:format\)/, "")}"
              }
            end
          end
        elsif framework == :sinatra
          ::Sinatra::Application.routes.each do |method, routes|
            routes.map { |r| r.first.to_s }.map do |route|
              NewRelic::Security::Agent.agent.route_map << "#{method}@#{route}"
            end
          end
        elsif framework == :grape
          ObjectSpace.each_object(::Grape::Endpoint) { |z|
            z.routes.each { |route|
              NewRelic::Security::Agent.agent.route_map << "#{route.options[:method]}@#{route.pattern.origin}"
            }
          }
        elsif framework == :padrino
          if router.instance_of?(::Padrino::PathRouter::Router)
            router.instance_variable_get(:@routes).each do |route|
              NewRelic::Security::Agent.agent.route_map << "#{route.instance_variable_get(:@verb)}@#{route.matcher.instance_variable_get(:@path)}"
            end
          end
        elsif framework == :roda
          NewRelic::Security::Agent.logger.warn "TODO: Roda is a routing tree web toolkit, which generates route dynamically, hence route extraction is not possible."
        else
          NewRelic::Security::Agent.logger.error "Unable to get app routes as Framework not detected"
        end
        disable_object_space_in_jruby if NewRelic::Security::Agent.config[:jruby_objectspace_enabled]
        NewRelic::Security::Agent.logger.debug "ALL ROUTES : #{NewRelic::Security::Agent.agent.route_map}"
        NewRelic::Security::Agent.agent.event_processor&.send_application_url_mappings
      rescue Exception => exception
        NewRelic::Security::Agent.logger.error "Error in get app routes : #{exception.inspect} #{exception.backtrace}"
      end

      def app_port(env)
        listen_port = nil
        if env.key?('puma.socket')
          NewRelic::Security::Agent.config.app_server = :puma
          if env['puma.socket'].is_a?(TCPSocket)
            listen_port = env['puma.socket'].addr[1]
            NewRelic::Security::Agent.logger.debug "Detected port from puma.socket TCPSocket : #{listen_port}"
          elsif env['puma.socket'].is_a?(Puma::MiniSSL::Socket)
              listen_port = env['puma.socket'].instance_variable_get(:@socket).addr[1]
              NewRelic::Security::Agent.logger.debug "Detected port from puma.socket Puma::MiniSSL::Socket TCPSocket : #{listen_port}"
          end
        end
        if env.key?('unicorn.socket') && env['unicorn.socket'].is_a?(::Unicorn::TCPClient)
          NewRelic::Security::Agent.config.app_server = :unicorn
          listen_port, _ = ::Socket.unpack_sockaddr_in(env['unicorn.socket'].getsockname)
          NewRelic::Security::Agent.logger.debug "Detected port from unicorn.socket Unicorn::TCPClient : #{listen_port}"
        end
        ObjectSpace.each_object(::Falcon::Server) { |z|
          NewRelic::Security::Agent.config.app_server = :falcon
          listen_port = z.endpoint.instance_variable_get(:@specification)[1]
          NewRelic::Security::Agent.logger.debug "Detected port from Falcon::Server : #{listen_port}"
        } if defined?(::Falcon::Server)
        ObjectSpace.each_object(::Thin::Backends::TcpServer) { |z|
          NewRelic::Security::Agent.config.app_server = :thin
          listen_port = z.instance_variable_get(:@port)
          NewRelic::Security::Agent.logger.debug "Detected port from Thin::Backends::TcpServer : #{listen_port}"
        } if defined?(::Thin::Backends::TcpServer)
        ObjectSpace.each_object(::WEBrick::GenericServer) { |z|
          NewRelic::Security::Agent.config.app_server = :webrick
          listen_port = z.instance_variable_get(:@config)[:Port]
          NewRelic::Security::Agent.logger.debug "Detected port from WEBrick::GenericServer : #{listen_port}"
        } if defined?(::WEBrick::GenericServer)
        if NewRelic::Security::Agent.config[:'security.application_info.port'] != 0
          listen_port = NewRelic::Security::Agent.config[:'security.application_info.port']
          NewRelic::Security::Agent.logger.info "Using application listen port from newrelic.yml security.application_info.port : #{listen_port}"
        end
        if listen_port
          NewRelic::Security::Agent.logger.info "Detected application listen_port : #{listen_port}"
        else
          NewRelic::Security::Agent.logger.warn "Unable to detect application listen port, IAST can not run without application listen port. Please provide application listen port in security.application_info.port in newrelic.yml"
        end
        disable_object_space_in_jruby if NewRelic::Security::Agent.config[:jruby_objectspace_enabled]
        listen_port
      rescue Exception => exception
        NewRelic::Security::Agent.logger.error "Exception in port detection : #{exception.inspect} #{exception.backtrace}"
      end

      def app_root
        #so far assuming it as Rails
        #TBD, determing the frame work then use appropriate APIs
        #val = Rails.root
        root = nil
        root = ::Rack::Directory.new(EMPTY_STRING).root.to_s if defined? ::Rack
        root
      end

      def enable_object_space_in_jruby
        if RUBY_ENGINE == 'jruby' && !JRuby.objectspace
          JRuby.objectspace = true
          NewRelic::Security::Agent.config.jruby_objectspace_enabled = true
        end
      end

      def disable_object_space_in_jruby
        if RUBY_ENGINE == 'jruby' && JRuby.objectspace
          JRuby.objectspace = false
          NewRelic::Security::Agent.config.jruby_objectspace_enabled = false
        end
      end

      def license_key
        NewRelic::Security::Agent.config[:license_key]
      end

      def filtered_log(log)
        log.gsub(license_key, ASTERISK * license_key.size)
      end
    end
  end
end
