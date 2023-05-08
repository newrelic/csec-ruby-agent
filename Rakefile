# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'

gemfile = 'Gemfile_test'
task :test_bundle do
    File.open(gemfile, 'w') do |f|
      f.puts "source 'https://rubygems.org'\n"
      f.puts "gem 'curb'"
      f.puts "gem 'excon'"
      f.puts "gem 'faraday'"
      f.puts "gem 'httpclient'"
      f.puts "gem 'net-http-persistent'"
      f.puts "gem 'net-ldap'"
      f.puts "gem 'nokogiri'"
      f.puts "gem 'patron'"
    end
    exec("bundle install --gemfile " + gemfile)
end

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/*_test.rb']
end

require 'rubocop/rake_task'

RuboCop::RakeTask.new

task default: %i[test rubocop]
