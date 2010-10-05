require 'ruby-saml'
require 'rspec'

Dir['./spec/support/**/*'].each { |f| require f }

RSpec::configure do |config|
  config.mock_with :rspec 
  config.color_enabled = true
  config.run_all_when_everything_filtered = true
  config.filter_run :focused => true
  config.formatter = :documentation
  config.backtrace_clean_patterns << %r{\.rvm}
  config.fail_fast = true
end

