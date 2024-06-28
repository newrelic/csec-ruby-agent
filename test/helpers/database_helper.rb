require 'docker'
# Uncomment below line and update username to test on mac with docker desktop
# Docker.authenticate!('username' => '<docker-username>') 

module NewRelic::Security
  module Test
    MYSQL_HOST = '127.0.0.1'
    MYSQL_PORT = 3307
    MYSQL_USERNAME = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DATABASE = 'testdb'

    MONGODB_URL = 'localhost:27018'
    MONGODB_DATABASE = 'testdb'

    POSTGRESQL_HOST = 'localhost'
    POSTGRESQL_PORT = '5433'
    POSTGRESQL_USER = 'postgres'
    POSTGRESQL_DATABASE = 'postgres'

    ELASTICSEARCH_HOST = 'localhost'
    ELASTICSEARCH_PORT = '9200'

    module DatabaseHelper
      extend self

      MYSQL_CONFIG = {
        'Image' => 'mysql:latest',
        'name' => 'mysql_test',
        'Env' => ['MYSQL_ALLOW_EMPTY_PASSWORD=yes', 'MYSQL_USER=test', 'MYSQL_DATABASE=testdb'],
        'HostConfig' => {
          'PortBindings' => {
            '3306/tcp' => [{ 'HostPort' => MYSQL_PORT.to_s }]
          }
        }
      }

      def create_mysql_container
        image = Docker::Image.create('fromImage' => 'mysql:latest')
        image.refresh!
        begin
            Docker::Container.get('mysql_test').remove(force: true)
        rescue
        end
        container = Docker::Container.create(MYSQL_CONFIG)
        container.start
        sleep 15
      end

      def remove_mysql_container
        begin
          Docker::Container.get('mysql_test').remove(force: true)
        rescue 
        end
      end

      MONGO_CONFIG = {
        'Image' => 'mongo:latest',
        'name' => 'mongo_test',
        'HostConfig' => {
          'PortBindings' => {
              '27017/tcp' => [{ 'HostPort' => '27018' }]
          }
        }
      }

      def create_mongodb_container
        image = Docker::Image.create('fromImage' => 'mongo:latest')
        image.refresh!
        begin
            Docker::Container.get('mongo_test').remove(force: true)
        rescue
        end
        container = Docker::Container.create(MONGO_CONFIG)
        container.start
        sleep 5
      end

      def remove_mongodb_container
        begin
          Docker::Container.get('mongo_test').remove(force: true)
        rescue
        end
      end

      POSTGRESQL_CONFIG = {
            'Image' => 'postgres:latest',
            'name' => 'pg_test',
            'Env' => ['POSTGRES_HOST_AUTH_METHOD=trust'],
            'HostConfig' => {
                'PortBindings' => {
                '5432/tcp' => [{ 'HostPort' => POSTGRESQL_PORT }]
                }
            }
        }

      def create_postgresql_container
        image = Docker::Image.create('fromImage' => 'postgres:latest')
        image.refresh!
        begin
            Docker::Container.get('pg_test').remove(force: true)
        rescue
        end
        container = Docker::Container.create(POSTGRESQL_CONFIG)
        container.start
        sleep 5
      end

      def remove_postgresql_container
        begin
          Docker::Container.get('pg_test').remove(force: true)
        rescue
        end
      end

      ELASTICSEARCH_CONFIG = {
            'Image' => 'elasticsearch:8.14.1',
            'name' => 'es_test',
            'Env' => ['discovery.type=single-node',
                      'xpack.security.enabled=false'],
            'HostConfig' => {
                'PortBindings' => {
                '9200/tcp' => [{ 'HostPort' => ELASTICSEARCH_PORT }]
                }
            }
        }

      def create_elasticsearch_container
        image = Docker::Image.create('fromImage' => 'elasticsearch:8.14.1')
        image.refresh!
        begin
            Docker::Container.get('es_test').remove(force: true)
        rescue
        end
        container = Docker::Container.create(ELASTICSEARCH_CONFIG)
        container.start
        sleep 10
      end

      def remove_elasticsearch_container
        begin
          Docker::Container.get('es_test').remove(force: true)
        rescue
        end
      end

    end
  end
end