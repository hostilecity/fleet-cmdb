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

  # Counts the SQL queries a block runs, ignoring schema and transaction statements.
  def count_queries
    count = 0
    counter = ->(*, payload) { count += 1 unless payload[:name].in?(%w[SCHEMA TRANSACTION]) || payload[:sql].match?(/\A\s*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)/i) }
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
