module NewRelic::Security
  module Agent
    module Logging
      class NullLogger
        def fatal(msg); end
  
        def error(msg); end
  
        def warn(msg); end
  
        def info(msg); end
  
        def debug(msg); end
  
        # def method_missing(method, *args, &blk)
        #   nil
        # end
      end
    end
  end
end