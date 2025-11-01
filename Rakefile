require 'rspec/core/rake_task'

task default: :spec

desc 'Run RSpec tests'
RSpec::Core::RakeTask.new(:spec) do |task|
  task.pattern = 'spec/**/*_spec.rb'
  task.rspec_opts = '--format documentation --color'
end

desc 'Run tests with coverage'
task :coverage do
  ENV['COVERAGE'] = 'true'
  Rake::Task[:spec].invoke
end

desc 'Run linter'
task :lint do
  puts 'Running RuboCop...'
  system('bundle exec rubocop lib spec bin')
end

desc 'Format code'
task :format do
  puts 'Formatting code with RuboCop...'
  system('bundle exec rubocop -a lib spec bin')
end

desc 'Build gem'
task :build do
  system('gem build streamripper.gemspec')
end

desc 'Install gem locally'
task :install => :build do
  system('gem install streamripper-*.gem')
end

desc 'Clean build artifacts'
task :clean do
  system('rm -f streamripper-*.gem')
  system('rm -rf pkg/')
end

