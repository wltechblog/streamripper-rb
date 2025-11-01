Gem::Specification.new do |spec|
  spec.name          = 'streamripper'
  spec.version       = '0.1.0'
  spec.authors       = ['Paul Philippov']
  spec.email         = ['themactep@gmail.com']
  spec.summary       = 'RTSP Stream Analyzer - Capture and analyze IP camera streams'
  spec.description   = 'A Ruby CLI tool to fetch, analyze, and log RTSP streams from IP cameras with forensic capabilities'
  spec.homepage      = 'https://github.com/themactep/streamripper-rb'
  spec.license       = 'MIT'

  spec.files         = Dir['lib/**/*.rb', 'bin/*', 'README.md', 'LICENSE']
  spec.bindir        = 'bin'
  spec.executables   = ['streamripper']
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.7.0'

  spec.add_dependency 'thor', '~> 1.2'
  spec.add_dependency 'json', '~> 2.6'
  spec.add_dependency 'base64', '~> 0.2'

  spec.add_development_dependency 'rspec', '~> 3.12'
  spec.add_development_dependency 'rspec-mocks', '~> 3.12'
  spec.add_development_dependency 'pry', '~> 0.14'
  spec.add_development_dependency 'rubocop', '~> 1.40'
end

