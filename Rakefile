# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'
require "#{File.dirname(__FILE__)}/lib/tasks/all.rb"

desc 'Install dependencies needed to run tests'
task :test_bundle do
  if RUBY_VERSION < '2.5.0'
    sh 'gem install bundler -v 1.17.2'
    exec('bundle _1.17.2_ install --gemfile Gemfile_test')
    exec('bundle _1.17.2_ update --gemfile Gemfile_test')
  else
    exec('bundle install --gemfile Gemfile_test')
  end
end

Rake::TestTask.new(:test) do |t|
  # ENV['BUNDLE_GEMFILE'] = 'Gemfile_test'
  t.libs << 'test'
  t.libs << 'lib'
  ENV['TESTOPTS'] = '--verbose'
  t.test_files = FileList['test/**/*_test.rb']
end

task :rubocop do
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new
end
