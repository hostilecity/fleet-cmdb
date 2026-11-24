require "rails_helper"
require Rails.root.join("db/migrate/20261122274003_add_backport_verdicts")

# #274, review N4: a version of its own, and safe on a database that has the columns already (one that ran an earlier
# head of #294, where they came from 20261122274002).
RSpec.describe AddBackportVerdicts do
  it "adds the columns only when they are missing" do
    migrate = ->(direction) { ActiveRecord::Migration.suppress_messages { described_class.new.migrate(direction) } }
    expect { migrate.(:up) }.not_to raise_error # the schema has them
    expect(ChunkMatch.column_names).to include("from_fixed_version", "keep_only")
  end
end
