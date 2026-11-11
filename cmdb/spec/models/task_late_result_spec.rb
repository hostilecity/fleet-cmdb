require "rails_helper"

# P3-S04: a late result is kept beside its task, once, and never changed or deleted.
RSpec.describe TaskLateResult do
  let(:task) do
    task = create_task
    task.expire!(actor: Audit::SYSTEM)
  end

  def late(**attributes)
    task.create_late_result!({ report_id: "00000000-0000-4000-8000-000000000001", outcome: "succeeded", agent_finished_at: Time.current,
                               digest: "0" * 64, received_at: Time.current, created_at: Time.current }.merge(attributes))
  end

  it "is read-only once saved, and never deleted" do
    record = late
    expect(record).to be_readonly
    expect { record.destroy }.to raise_error(ActiveRecord::ReadOnlyRecord)
  end

  it "refuses an outcome outside the result outcomes" do
    expect { late(outcome: "expired") }.to raise_error(ActiveRecord::RecordInvalid)
  end

  # Each refused statement runs in its own savepoint, so the next one can run.
  def in_savepoint(&) = described_class.transaction(requires_new: true, &)

  it "is guarded in the database: no update, delete, or truncate, and one per task" do
    record = late
    expect { in_savepoint { described_class.where(id: record.id).update_all(outcome: "failed") } }.to raise_error(ActiveRecord::StatementInvalid, /never changed or deleted/)
    expect { in_savepoint { described_class.where(id: record.id).delete_all } }.to raise_error(ActiveRecord::StatementInvalid, /never changed or deleted/)
    expect { in_savepoint { described_class.connection.execute("TRUNCATE task_late_results CASCADE") } }.to raise_error(ActiveRecord::StatementInvalid, /never changed or deleted/)
    expect { in_savepoint { described_class.insert_all!([ record.attributes.except("id") ]) } }.to raise_error(ActiveRecord::RecordNotUnique)
  end
end
