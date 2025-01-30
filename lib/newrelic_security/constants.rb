# frozen_string_literal: true

module NewRelic::Security
  EMPTY_STRING = ""
  RUBY = 'RUBY'
  Ruby = 'Ruby'
  LANGUAGE_COLLECTOR = 'LANGUAGE_COLLECTOR'
  STANDARD_OUT = 'STDOUT'
  NR_CSEC_VALIDATOR_HOME_TMP = '{{NR_CSEC_VALIDATOR_HOME_TMP}}'
  NR_CSEC_VALIDATOR_HOME_TMP_URL_ENCODED = '%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D'
  NR_CSEC_VALIDATOR_FILE_SEPARATOR = '{{NR_CSEC_VALIDATOR_FILE_SEPARATOR}}'
  SEC_HOME_PATH = 'nr-security-home'
  LOGS_DIR = 'logs'
  TMP_DIR = 'tmp'
  LOG_FILE_NAME = 'ruby-security-collector.log'
  NR_SECURITY_HOME_TMP = 'nr-security-home/tmp/'
  NR_CSEC_FUZZ_REQUEST_ID = 'nr-csec-fuzz-request-id'
  NR_CSEC_TRACING_DATA = 'nr-csec-tracing-data'
  NR_CSEC_PARENT_ID = 'nr-csec-parent-id'
  IAST = 'IAST'
  COLON_IAST_COLON = ':IAST:'
  NOSQL_DB_COMMAND = 'NOSQL_DB_COMMAND'
  SQL_DB_COMMAND = 'SQL_DB_COMMAND'
  FILE_OPERATION = 'FILE_OPERATION'
  FILE_INTEGRITY = 'FILE_INTEGRITY'
  SYSTEM_COMMAND = 'SYSTEM_COMMAND'
  REFLECTED_XSS = 'REFLECTED_XSS'
  HTTP_REQUEST = 'HTTP_REQUEST'
  XPATH = 'XPATH'
  LDAP = 'LDAP'
  MONGO = 'MONGO'
  SQLITE = 'SQLITE'
  MYSQL = 'MYSQL'
  POSTGRES = 'POSTGRES'
  EQUAL = '='
  SECURE_COOKIE = 'SECURE_COOKIE'
  SET_COOKIE = 'Set-Cookie'
  BACKSLASH_N = "\n"
  SEMICOLON_SPACE = '; '
  ISO_8859_1 = 'ISO-8859-1'
  UTF_8 = 'UTF-8'
  RAILS = 'rails'
  PUMA = 'puma'
  CLUSTER = 'cluster'
  UNICORN = 'unicorn'
  WORKER = 'worker'
  HYPHEN = '-'
  COMMA = ','
  SLASH = '/'
  AT_THE_RATE = '@'
  SPAWN_METHOD = 'spawn_method'
  DIRECT = 'direct'
  LISTEN_PORT = 'listen_port'
  PIPE = '|'
  READ = 'read'
  DELETE = 'delete'
  WRITE = 'write'
  BINWRITE = 'binwrite'
  PROTOCOL = 'protocol'
  HTTPS = 'https'
  REQUEST_METHOD = 'REQUEST_METHOD'
  PATH_INFO = 'PATH_INFO'
  CONTENT_TYPE = 'CONTENT_TYPE'
  REQUEST_URI = 'REQUEST_URI'
  SERVER_PORT = 'SERVER_PORT'
  X_FORWARDED_FOR = 'x-forwarded-for'
  REMOTE_ADDR = 'REMOTE_ADDR'
  RACK_URL_SCHEME = 'rack.url_scheme'
  CONTENT_TYPE1 = 'content-Type'
  PULL = 'PULL'
  SHA1 = 'sha1'
end