# Helpers for dashboard specs (P1-DASH-FLEET).
module DashboardHelpers
  def inventory_example(name = "full")
    ApiContract.example("inventory.request", name)
  end

  # Stores an inventory report for an enrolled host through InventoryRecorder, as the endpoint does.
  def record_inventory(host, name: "full", **overrides)
    payload = inventory_example(name).merge("report_id" => SecureRandom.uuid).merge(overrides.transform_keys(&:to_s))
    Host.transaction do
      InventoryRecorder.record!(host_id: host.id, credential_id: host.agent_credentials.active.pick(:id),
                                report: AgentApi::InventoryReport.new(payload))
    end
  end

  def sign_in_operator(email: "operator@example.com")
    allow_operator(email) unless OperatorAllowlistEntry.allowed?(email)
    sign_in_with_google(email:)
  end

  # Statements count_queries leaves out: schema and transaction statements, and the two that check a page's replica
  # has caught up (ReplicaReads, #198), which are the same on every page.
  UNCOUNTED_NAMES = [ "SCHEMA", "TRANSACTION", "Replica target", "Replica caught up" ].freeze
  UNCOUNTED_SQL = /\A\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)/i
  # Also left out: the SET search_path a connection runs when it connects, to config/database.yml's
  # schema_search_path and nothing else (#313). It is the one connection setup statement Rails names "SQL" rather than
  # "SCHEMA". It runs when a pool is first used in a process, such as the queue database for the failed-jobs banner,
  # and that may be inside the block. Any other SET search_path counts: search_path is a recorded control (#239).
  CONNECTION_SETUP = "SET search_path TO #{ApplicationRecord.connection_db_config.configuration_hash.fetch(:schema_search_path)}".freeze
  # Active Record's pool reaper thread reconnects idle pool connections in the background (every 20 s), each with its
  # SET search_path. The subscription is process-wide, so one that landed inside the block was counted (#313).
  REAPER_THREAD = "AR Pool Reaper".freeze

  # Counts the SQL statements a block runs. They must all run on this thread, which runs a request spec's page and a
  # model spec's code, apart from the pool reaper's, which are left out. A statement from any other thread fails the
  # example: an upper-limit budget would otherwise read a statement it missed as an improvement.
  def count_queries
    count = 0
    thread = Thread.current
    elsewhere = Thread::Queue.new
    counter = lambda do |*, payload|
      next if payload[:name].in?(UNCOUNTED_NAMES) || payload[:sql].match?(UNCOUNTED_SQL) || payload[:sql] == CONNECTION_SETUP

      if Thread.current == thread then count += 1
      elsif Thread.current.name != REAPER_THREAD then elsewhere << "#{Thread.current.name || Thread.current.inspect}: #{payload[:sql].squish.truncate(200)}"
      end
    end
    ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { yield }
    unless elsewhere.empty?
      found = Array.new(elsewhere.size) { elsewhere.pop }
      RSpec::Expectations.fail_with("count_queries counts the statements of the block's own thread only, but #{found.size} ran on another " \
                                    "thread inside it, so the budget would not see them:\n  #{found.join("\n  ")}")
    end
    count
  end
end

module PageHelpers
  # The response as an HTML document, for CSS queries.
  def page = Nokogiri::HTML(response.body)
end

# Dashboard pages as the signed-in operator@example.com: tag a group :signed_in.
RSpec.shared_context "signed in operator" do
  let(:operator) { Operator.find_by!(email: "operator@example.com") }

  before { sign_in_operator }
end

RSpec.configure do |config|
  config.include DashboardHelpers
  config.include PageHelpers, type: :request
  config.include_context "signed in operator", :signed_in
end
