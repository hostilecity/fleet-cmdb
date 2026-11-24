require "rails_helper"

# The statement budgets' counter (spec/support/dashboard_helpers.rb, #313): only the block's own statements count.
RSpec.describe DashboardHelpers, "#count_queries" do
  it "leaves out statements run on other threads, as the pool reaper's reconnects are" do
    queries = count_queries do
      Thread.new { ApplicationRecord.connection_pool.with_connection { |c| c.select_value("SELECT 1") } }.join
      Operator.count
    end
    expect(queries).to eq(1)
  end

  it "leaves out a connection's setup when it connects inside the block, its SET search_path included" do
    session = ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.new(ApplicationRecord.connection_db_config.configuration_hash)
    queries = count_queries { session.select_value("SELECT 1") }
    expect(queries).to eq(1)
  ensure
    session&.disconnect!
  end
end
