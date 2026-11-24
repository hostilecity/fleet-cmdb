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
  # Also left out: the SET search_path a connection runs when it connects (config/database.yml's schema_search_path,
  # #313). It is the one connection setup statement Rails names "SQL" rather than "SCHEMA". It runs when a pool is
  # first used in a process, such as the queue database for the failed-jobs banner, and that may be inside the block.
  UNCOUNTED_SQL = /\A\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|SET search_path TO )/i

  # Counts the SQL statements a block runs on this thread, which runs a request spec's page and a model spec's code.
  # Statements from other threads are not the block's (#313): the subscription is process-wide, and Active Record's
  # pool reaper thread reconnects idle pool connections in the background (every 20 s), each with its SET
  # search_path. One that landed inside the block made the budgets count one statement too many now and then.
  def count_queries
    count = 0
    thread = Thread.current
    counter = lambda do |*, payload|
      count += 1 if Thread.current == thread && !payload[:name].in?(UNCOUNTED_NAMES) && !payload[:sql].match?(UNCOUNTED_SQL)
    end
    ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { yield }
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
