require "rails_helper"
require Rails.root.join("db/migrate/20261107060000_add_skipped_and_unreadable_to_packages")

# Rolling back the skipped and unreadable package migration (P2-S08, review of #121): the previous constraints cannot
# hold an unreadable set or snapshot, so the rollback refuses while one exists rather than rewrite it as unsupported.
RSpec.describe AddSkippedAndUnreadableToPackages do
  let(:host) { enrolled_host.first }

  def migrate_down = ActiveRecord::Migration.suppress_messages { described_class.new.migrate(:down) }

  def constraints(table) = ActiveRecord::Base.connection.check_constraints(table).map(&:name).sort

  it "refuses to roll back while an unreadable package set or snapshot exists, and changes nothing" do
    report_packages(host, [], manager: "unreadable", unsupported_reason: "dpkg-query exited with status 2")
    before = [ constraints(:host_package_sets), constraints(:package_snapshots) ]
    expect { migrate_down }.to raise_error(ActiveRecord::IrreversibleMigration, /1 host_package_sets rows and 1 package_snapshots rows have manager 'unreadable'/)
    expect([ constraints(:host_package_sets), constraints(:package_snapshots) ]).to eq(before)
    expect(HostPackageSet.find_by!(host_id: host.id)).to be_unreadable
  end

  it "rolls back to the previous constraints when no unreadable row exists" do
    report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ], skipped: [ { "name" => "vim", "reason" => "unpacked" } ])
    migrate_down
    expect(constraints(:host_package_sets)).to eq(%w[host_package_sets_manager_valid host_package_sets_reason_iff_unsupported])
    expect(ActiveRecord::Base.connection.column_exists?(:package_snapshots, :skipped)).to be(false)
  end
end
