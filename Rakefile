# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'

desc 'Install dependencies needed to run tests'
task :test_bundle do
  exec('bundle install --gemfile Gemfile_test')
end

Rake::TestTask.new(:test) do |t|
  ENV["VERBOSE_TEST_OUTPUT"] = '1'
  ENV['BUNDLE_GEMFILE'] = 'Gemfile_test'
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/*_test.rb']
end

task :rubocop do
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new
end