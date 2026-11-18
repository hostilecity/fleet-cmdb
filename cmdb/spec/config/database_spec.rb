require "rails_helper"

# The cable database (#194, reviews of #212 and #218): a connection attempt fails within 2 s, an error Solid Cable's
# listener retries, and no statement timeout, whose cancelled poll would stop the listener thread for good.
RSpec.describe "config/database.yml" do
  def cable(env) = ActiveRecord::Base.configurations.configs_for(env_name: env, name: "cable").configuration_hash

  it "gives the cable database a 2 s connect timeout and no statement timeout wherever it is a database" do
    %w[development production].each do |env|
      expect(cable(env)).to include(connect_timeout: 2), env
      expect(cable(env).fetch(:variables, {}).keys.map(&:to_s)).not_to include("statement_timeout"), env
    end
  end
end

# The optional scale settings (#198): off by default, so production has the four databases as before; a transaction
# pooler turns off prepared statements and the migration lock on the pooled databases only; a direct database and a
# replica appear only when their URLs are set, and neither is ever migrated on its own.
RSpec.describe "config/database.yml with the scale settings (#198)" do
  KEYS = %w[FLEET_DB_POOLER DIRECT_DATABASE_URL REPLICA_DATABASE_URL FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS].freeze

  def production(env = {})
    saved = KEYS.to_h { |key| [ key, ENV.fetch(key, nil) ] }
    KEYS.each { |key| ENV.delete(key) }
    env.each { |key, value| ENV[key] = value }
    Rails.application.config.database_configuration.fetch("production").transform_values(&:symbolize_keys)
  ensure
    saved.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  it "has the four databases, with prepared statements and advisory locks as Rails defaults them, when nothing is set" do
    configs = production
    expect(configs.keys).to eq(%w[primary cache queue cable])
    configs.each_value { |config| expect(config.keys).not_to include(:prepared_statements, :advisory_locks) }
  end

  it "turns off prepared statements and the migration lock behind a transaction pooler, but not on the direct database" do
    configs = production("FLEET_DB_POOLER" => "transaction", "DIRECT_DATABASE_URL" => "postgres://db.example.lan/cmdb_production")
    expect(configs.keys).to eq(%w[primary cache queue cable direct])
    configs.slice("primary", "cache", "queue", "cable").each_value { |config| expect(config).to include(prepared_statements: false, advisory_locks: false) }
    expect(configs.fetch("direct")).to include(database: "cmdb_production", username: "cmdb", database_tasks: false, prepared_statements: true, advisory_locks: true)
  end

  it "adds the replica, read-only and never migrated, only when REPLICA_DATABASE_URL is set" do
    configs = production("REPLICA_DATABASE_URL" => "postgres://replica.example.lan/cmdb_production")
    expect(configs.keys).to eq(%w[primary cache queue cable replica])
    expect(configs.fetch("replica")).to include(database: "cmdb_production", username: "cmdb", replica: true, connect_timeout: 2)
    slow = production("REPLICA_DATABASE_URL" => "postgres://replica.example.lan/cmdb_production", "FLEET_REPLICA_CONNECT_TIMEOUT_SECONDS" => "5")
    expect(slow.fetch("replica")).to include(connect_timeout: 5)
  end

  it "stops the boot on a transaction pooler without a direct database" do
    expect { production("FLEET_DB_POOLER" => "transaction") }.to raise_error(/needs DIRECT_DATABASE_URL/)
  end

  it "gives the test environment a replica on the test database, so the replica's pages run with writes refused" do
    replica = ActiveRecord::Base.configurations.configs_for(env_name: "test", name: "replica", include_hidden: true)
    expect(replica).to be_replica
    expect(replica.database).to eq(ApplicationRecord.connection_db_config.database)
  end
end
