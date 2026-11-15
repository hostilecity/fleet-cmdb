# Live refreshes waiting to be sent (#194, LiveRefresh): one row per Turbo stream with a change not yet broadcast,
# plus one marker row while a flush job is scheduled. Rows live seconds; nothing else refers to them.
class CreatePendingRefreshes < ActiveRecord::Migration[8.1]
  def change
    create_table :pending_refreshes, id: false do |t|
      t.string :stream, limit: 128, null: false, primary_key: true
      t.datetime :requested_at, null: false, default: -> { "statement_timestamp()" }
    end
  end
end
