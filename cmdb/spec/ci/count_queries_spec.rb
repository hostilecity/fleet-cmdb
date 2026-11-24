require "rails_helper"

# The statement budgets' counter (spec/support/dashboard_helpers.rb, #313): only the block's own statements count.
RSpec.describe DashboardHelpers, "#count_queries" do
  # A statement run on a thread of its own, named name, while the block runs.
  def on_thread(name, sql = "SELECT 1")
    Thread.new do
      Thread.current.name = name
      ApplicationRecord.connection_pool.with_connection { |c| c.select_value(sql) }
    end.join
  end

  # A connection of its own, outside the pools, connected on first use.
  def separate_connection = ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.new(ApplicationRecord.connection_db_config.configuration_hash)

  it "leaves out the pool reaper thread's statements, which reconnect idle connections in the background" do
    expect(count_queries { on_thread("AR Pool Reaper") && Operator.count }).to eq(1)
  end

  it "fails the example when any other thread runs a statement inside the block, so an upper-limit budget cannot miss it" do
    expect { count_queries { on_thread("matcher worker", "SELECT 2") && Operator.count } }
      .to raise_error(RSpec::Expectations::ExpectationNotMetError, /1 ran on another thread inside it.*\n  matcher worker: SELECT 2/)
  end

  it "leaves out a connection's setup when it connects inside the block, its SET search_path to the configured path included" do
    session = separate_connection
    expect(count_queries { session.select_value("SELECT 1") }).to eq(1)
  ensure
    session&.disconnect!
  end

  it "counts a SET search_path to any other path" do
    session = separate_connection
    session.select_value("SELECT 1") # connected before the block
    expect(count_queries { session.execute("SET search_path TO public, pg_catalog") }).to eq(1)
  ensure
    session&.disconnect!
  end
end
