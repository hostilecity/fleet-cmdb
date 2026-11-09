require "rails_helper"

RSpec.describe TaskBatch do
  it "is read-only once created, in the model and in the database (task_batches_guard)" do
    batch = create_task_batch([ task_host ]).batch
    expect(batch).to be_readonly
    expect { batch.update!(task_type: "apply_package_updates") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    expect { TaskBatch.transaction(requires_new: true) { TaskBatch.where(id: batch.id).update_all(parameters: { "x" => 1 }) } }
      .to raise_error(ActiveRecord::StatementInvalid, /task batches are never changed or deleted: UPDATE/)
    expect { TaskBatch.transaction(requires_new: true) { TaskBatch.where(id: batch.id).delete_all } }
      .to raise_error(ActiveRecord::StatementInvalid, /DELETE is not allowed/)
  end

  it "counts its tasks by state, listing every state" do
    result = create_task_batch(Array.new(2) { task_host })
    result.tasks.first.expire!(actor: Audit::SYSTEM)
    expect(result.batch.state_counts).to eq(Task::STATES.index_with(0).merge("queued" => 1, "expired" => 1))
  end

  it "accepts only the two selection methods" do
    expect(TaskBatch.new(selection_method: "everything")).not_to be_valid
  end
end
