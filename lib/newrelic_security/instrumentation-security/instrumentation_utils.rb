# frozen_string_literal: true
require 'set'

module NewRelic::Security
  module Instrumentation
    module InstrumentationUtils
      extend self

      OPEN_MODES = ::Set.new(%W[r rb])
      APP_INTEGRITY_MODES = ::Set.new(%W[w w+ a a+ ab at r+ wb wt write binwrite])
      DOT_DOT_SLASH = '../'
      TMP_CACHE = '/tmp/cache'
      FILTERED_SQL = ['PRAGMA foreign_keys = ON', #sqlite
        'COMMIT',   #mysql
        'BEGIN',   #mysql
        'PRAGMA', #sqlite
        'begin deferred transaction', #sqlite
        'commit transaction', #sqlite
        'SHOW TIME ZONE', #pg
        'SET' #pg
      ]

      def sql_filter_events?(sql_query)
        FILTERED_SQL.each do |unwanted_sql|
          if sql_query.start_with?(unwanted_sql)
            NewRelic::Security::Agent.logger.debug "Filtered invalid SQL '#{sql_query}'"
            return true
          end
        end if sql_query
        return false
      end

      def in_app_dir?(fname, abs_path)
        app_dir = NewRelic::Security::Agent.config[:app_root]
        if app_dir == nil
          return false
        end
        if abs_path.start_with?(app_dir)
          return true
        end
        return false
      end
  
      def in_gem_dir?(fname, abs_path)
        gem_dir = ::Gem.dir
        if gem_dir == nil
          return false
        end
        if abs_path.start_with?(gem_dir)
          return true
        end
        return false
      end
  
      def in_tmp_cache_dir?(fname, abs_path)
        app_dir = NewRelic::Security::Agent.config[:app_root]
        if app_dir == nil
          return false
        end
        if abs_path.start_with?(app_dir + TMP_CACHE)
          return true
        end
        return false
      end
  
      def notify_app_integrity_open?(fname, abs_path, fmode)
        if fname == nil || fmode == nil
          # we cannot do the app integrity
          NewRelic::Security::Agent.logger.debug "Invalid Args of 'open', app integrity check cannot be enforced  \r\n"
          NewRelic::Security::Agent.logger.debug "File Name #{fname} fmode  #{fmode}"
          return false
        end
        #check whether the file path is  in the App root directory
        #check whether file exists for 'w','w+','a','a+' mode because file is created
        #for these modes if it doesn't present.
        #If file already exists , then no need to send the app integrity event to IC
        if in_app_dir?(fname, abs_path) && !in_tmp_cache_dir?(fname, abs_path) && APP_INTEGRITY_MODES.include?(fmode)
            return true
        end
        return false
      end
  
      def notify_app_integrity_delete?(fnames)
        #delete api argument is an array of file names/name
        #get the root directory
        #check whether file present in the application root
        #check whether the file exists, if not remove it from the args
        if fnames == nil || fnames.empty?
          NewRelic::Security::Agent.logger.debug "Invalid Args of 'delete', app integrity check cannot be enforced  \r\n"
          return false
        end
        NewRelic::Security::Agent.logger.debug "File Names  #{fnames}"
        fnames.each do |fname|
          return true if in_app_dir?(fname, ::File.expand_path(fname)) && !in_tmp_cache_dir?(fname, ::File.expand_path(fname))
        end
        return false
      end
      
      def open_filter?(fname, abs_path, fmode)
        if fname == nil || fmode == nil
          NewRelic::Security::Agent.logger.debug "Invalid Args of 'open', filter cannot be enforced  \r\n"
          NewRelic::Security::Agent.logger.debug "File Name #{fname} fmode  #{fmode}"
          return false
        end
        if (in_app_dir?(fname, abs_path) || in_gem_dir?(fname, abs_path)) && OPEN_MODES.include?(fmode)
          if !fname.include?(DOT_DOT_SLASH) #check for any path traversal
            return true #filter it , if path is in app_dir and there is no "../" segment
          end
        end
        return false
      end
  
      #for now ,any file read in the application directory event is filtered out.
      def read_filter?(fname, abs_path)
        if fname == nil
          NewRelic::Security::Agent.logger.debug "Invalid Args of 'read', filter cannot be enforced  \r\n"
          NewRelic::Security::Agent.logger.debug "File Name #{fname} "
          return false
        end
        if in_app_dir?(fname, abs_path) || in_gem_dir?(fname, abs_path) 
          if !fname.include?(DOT_DOT_SLASH) #check for any path traversal
            return true #filter it , if path is in app_dir and there is no "../" segment
          end
        end
        return false
      end

      def add_tracing_data(req, event)
        req[NR_CSEC_TRACING_DATA] = "#{event.httpRequest[:headers][NR_CSEC_TRACING_DATA]} #{NewRelic::Security::Agent.config[:uuid]}/#{event.apiId}/#{event.id};"
        req[NR_CSEC_FUZZ_REQUEST_ID] = event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID] if event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID]
      end

      def append_tracing_data(req, event)
        req.append([NR_CSEC_TRACING_DATA, "#{event.httpRequest[:headers][NR_CSEC_TRACING_DATA]} #{NewRelic::Security::Agent.config[:uuid]}/#{event.apiId}/#{event.id};"])
        req.append([NR_CSEC_FUZZ_REQUEST_ID, event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID]]) if event.httpRequest[:headers][NR_CSEC_FUZZ_REQUEST_ID]
      end

    end
  end
end