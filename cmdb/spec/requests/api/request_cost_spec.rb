require "rails_helper"

# The cost of the agent requests that make up most agent traffic (#189): statements per request, one transaction with
# authentication inside it, and the credential's last use written in that transaction, after the host lock. The
# heartbeat's own statements are checked in heartbeat_spec.rb.
RSpec.describe "Agent request cost", type: :request do
  let(:operator) { create(:operator) }
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }

  before do
    host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: TaskCatalog.current.types,
                        task_types_enabled: TaskCatalog.current.types, task_services_allowed: [], task_capabilities_reported_at: Time.current)
  end

  def poll = post_api("/api/v1/tasks/poll", { "schema_version" => 1, "agent_version" => "0.3.0" }, credential)

  # The statements of one request, savepoints and transaction control included, without schema queries.
  def statements_of
    statements = []
    callback = ->(*, payload) { statements << payload[:sql] unless payload[:name] == "SCHEMA" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
    statements
  end

  def queries(statements) = statements.grep_v(/\A(SAVEPOINT|RELEASE|ROLLBACK|BEGIN|COMMIT)/)

  def expect_one_transaction(statements)
    expect(statements.first).to match(/\ASAVEPOINT/) # the request's transaction, inside the test's
    expect(statements.last).to match(/\ARELEASE SAVEPOINT/)
    expect(statements.grep(/\A(SAVEPOINT|RELEASE|BEGIN|COMMIT)/).size).to eq(2), statements.inspect
  end

  describe "a task poll with nothing to do" do
    it "is four SELECTs in one transaction, and no write while the last use is recent" do
      poll # records the last use and warms the poll hint
      statements = statements_of { poll }
      expect(response).to have_http_status(:ok)
      expect_one_transaction(statements)
      sql = queries(statements)
      # authentication, the host lock joined to the credential, the host's running and claimed tasks, the queue
      expect(sql.size).to eq(4), sql.inspect
      expect(sql[1]).to match(/FOR UPDATE OF hosts FOR SHARE OF agent_credentials/)
      expect(sql[2]).to match(/FROM "tasks" WHERE .* ORDER BY "tasks"."id"/)
      expect(sql[3]).to match(/FOR UPDATE SKIP LOCKED/)
      expect(sql.grep(/\A\s*(UPDATE|INSERT|DELETE)/)).to be_empty
      expect(sql.join).not_to include('"settings"')
    end

    it "writes the last use at most every few minutes, in the request's transaction after the host lock" do
      poll
      travel(AgentCredential::LAST_USED_RESOLUTION + 1.second) do
        statements = statements_of { poll }
        expect_one_transaction(statements)
        update = statements.index { |sql| sql.match?(/\AUPDATE "agent_credentials" SET "last_used_at"/) }
        lock = statements.index { |sql| sql.include?("FOR UPDATE OF hosts") }
        expect(update).to be > lock
        expect(host.agent_credentials.active.sole.last_used_at).to eq(Time.current.floor(6))
      end
    end

    it "keeps no last use from a request that fails" do
      before = host.agent_credentials.active.sole.last_used_at
      post_api("/api/v1/tasks/poll", { "schema_version" => 1, "agent_version" => "0.0.1" }, credential) # below the minimum
      expect_error(:upgrade_required, "agent_version_unsupported")
      expect(host.agent_credentials.active.sole.last_used_at).to eq(before)
    end

    it "reads the poll hint at most once per process every few seconds" do
      statements = statements_of { 3.times { poll } }
      expect(statements.grep(/FROM "settings"/).size).to eq(1)
      TaskSettings.update_limits!({ "poll_seconds" => "60" }, actor: operator)
      poll
      expect(json["poll_seconds"]).to eq(60) # this process sees its own change at once
    end
  end

  it "names a running task to cancel from the same read of the host's tasks (P3-S05)" do
    task = TaskBatches.create!({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:).tasks.sole
    task.claim!(actor: host, lease_expires_at: 5.minutes.from_now)
    task.start!(actor: host, lease_expires_at: 15.minutes.from_now)
    TaskCancellation.cancel_task!(task, operator:)
    poll
    statements = statements_of { poll }
    expect(json).to include("task" => nil, "cancel" => { "id" => task.uuid })
    expect(queries(statements).size).to eq(3), statements.inspect # authentication, the host lock, the host's tasks
  end
end
