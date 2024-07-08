# frozen_string_literal: true
require 'digest'
require 'json'

module NewRelic::Security
  module Agent
    module Control
      
      PROC_SELF_EXE = '/proc/self/exe'
      PROC_SELF_CMDLINE = '/proc/self/cmdline'
      STATIC = 'STATIC'
      COLON = ':'
      RUBYLIB = 'RUBYLIB'
      BACKSLASH000 = '\000'
      KIND = 'kind'

      class AppInfo
        attr_reader :jsonName

        def initialize
          @collectorType = RUBY
          @language = Ruby
          @jsonName = :applicationinfo
          @collectorVersion = NewRelic::Security::VERSION
          @buildNumber = nil
          @jsonVersion = NewRelic::Security::Agent.config[:json_version]
          @startTime = current_time_millis
          @applicationUUID = NewRelic::Security::Agent.config[:uuid]
          @appAccountId = NewRelic::Security::Agent.config[:account_id]
          @appEntityGuid = NewRelic::Security::Agent.config[:entity_guid]
          @framework = NewRelic::Security::Agent.config[:framework]
          @groupName = NewRelic::Security::Agent.config[:mode]
          @userProvidedApplicationInfo = Hash.new
          @policyVersion = nil
          @userDir = nil
          @libraryPath = library_path
          @bootLibraryPath = EMPTY_STRING
          @binaryName = binary_name
          @binaryVersion = binary_version
          @pid = pid
          @cpid = cpid
          @binaryPath = binary_path
          @agentAttachmentType = STATIC
          @sha256 = sha_256
          @runCommand = run_command
          @cmdline = [run_command]
          @procStartTime = current_time_millis
          @osArch = os_arch
          @osName = os_name
          @osVersion = os_version
          @serverInfo = Hash.new # TODO: Fill this
          @identifier = Hash.new # TODO: Fill this
          @linkingMetadata = add_linking_metadata
        end

        def as_json
          instance_variables.map! do |ivar|
            [ivar[1..-1].to_sym, instance_variable_get(ivar)]
          end.to_h
        end

        def to_json
          as_json.to_json
        end

        def update_app_info
          @identifier[KIND] = 'HOST' # TODO: Added other identifier details
        end

        private 

        def current_time_millis
          (Time.now.to_f * 1000).to_i
        end

        def library_path
          ENV[RUBYLIB].split(COLON)
        end

        def binary_name
          RUBY_ENGINE
        end

        def binary_version
          RUBY_VERSION
        end

        def pid
          return ::Process.pid if ::Gem.win_platform?
          ::Process.getpgrp
        end

        def cpid
          Process.pid
        end

        def binary_path
          return ::File.realpath(PROC_SELF_EXE) if ::File.exist?(PROC_SELF_EXE)
          nil
        end

        def sha_256
          return ::Digest::SHA256.file(binary_path).hexdigest if binary_path
          nil
        end

        def run_command
          return ::File.read(PROC_SELF_CMDLINE).delete(BACKSLASH000) if File.exist?(PROC_SELF_CMDLINE)
          $PROGRAM_NAME
        end

        def os_arch
          ::Gem::Platform.local.cpu
        end

        def os_name
          ::Gem::Platform.local.os
        end

        def os_version
          ::Gem::Platform.local.version
        end

        def add_linking_metadata
          linking_metadata = Hash.new
          linking_metadata[:agentRunId] = NewRelic::Security::Agent.config[:agent_run_id]
          linking_metadata.merge!(NewRelic::Security::Agent.config[:linking_metadata])
          # TODO: add other fields as well in linking metadata, for event and heathcheck as well
        end

      end
    end
  end
end