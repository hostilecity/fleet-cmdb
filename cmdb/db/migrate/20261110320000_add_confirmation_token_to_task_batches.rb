# Create-task flow (P3-S08, threat model H10).
#
# confirmation_token is the one-time id of the confirmation page a dashboard batch was created from. Unique, so a
# second submit of the same page (a double click or a browser retry) cannot create a second batch. NULL for batches
# made without that page.
class AddConfirmationTokenToTaskBatches < ActiveRecord::Migration[8.1]
  def change
    add_column :task_batches, :confirmation_token, :uuid
    add_index :task_batches, :confirmation_token, unique: true
  end
end
