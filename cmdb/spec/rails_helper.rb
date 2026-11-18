require "spec_helper"
ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
abort("The Rails environment is running in production mode!") if Rails.env.production?
require "rspec/rails"
require "webmock/rspec"

# Tests never touch the network. Allow only the local database/app.
WebMock.disable_net_connect!(allow_localhost: true)

Rails.root.glob("spec/support/**/*.rb").sort.each { |f| require f }

begin
  ActiveRecord::Migration.maintain_test_schema!
rescue ActiveRecord::PendingMigrationError => e
  abort e.to_s.strip
end
# The schema holds the partitioned history tables' parents only (ADR 0027): their partitions are created here, as
# db:prepare does, and the audit log's months back two years, since it has no default partition and some examples
# date entries in the past. Other old rows land in each table's default partition.
Partitions.ensure!
Partitions.ensure!(tables: [ Partitions::AUDIT ], from: 2.years.ago)
Partitions.pause = 0

RSpec.configure do |config|
  config.fixture_paths = [ Rails.root.join("spec/fixtures") ]
  config.use_transactional_fixtures = true
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!
  config.include FactoryBot::Syntax::Methods
end
