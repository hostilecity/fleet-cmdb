# Helpers for dashboard specs (P1-DASH-FLEET).
module DashboardHelpers
  def inventory_example(name = "full")
    ApiContract.examples.find { |e| e.schema_name == "inventory.request" && e.kind == "valid" && e.name == name }.data
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

  # Counts the SQL queries a block runs, ignoring schema and transaction statements.
  def count_queries
    count = 0
    counter = ->(*, payload) { count += 1 unless payload[:name].in?(%w[SCHEMA TRANSACTION]) || payload[:sql].match?(/\A\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)/i) }
    ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { yield }
    count
  end
end

RSpec.configure do |config|
  config.include DashboardHelpers
end
