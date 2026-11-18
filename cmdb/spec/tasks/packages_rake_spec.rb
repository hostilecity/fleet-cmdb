require "rails_helper"
require "rake"

# bin/rails packages:check_snapshots (#196, ADR 0028): the package store's references, checked by hand.
RSpec.describe "packages rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "packages:check_snapshots" } }

  it "refuses while another backfill holds the lock" do
    allow(PackageStoreBackfill).to receive(:new).and_wrap_original do |original, **options|
      original.call(**options).tap { |b| allow(b).to receive_messages(needed?: true, pending: {}) }
    end
    Rake::Task["packages:backfill"].reenable
    holding_backfill_lock do
      expect { Rake::Task["packages:backfill"].invoke }.to raise_error(SystemExit).and output(/another package backfill is running/).to_stderr
    end
  end

  it "backfills nothing once the old storage is gone, and says so (spec/db/backfill_package_sets_spec.rb moves an old one)" do
    Rake::Task["packages:backfill"].reenable
    expect { Rake::Task["packages:backfill"].invoke }
      .to output("To move: 0 hashes, 0 unreadable hosts, 0 findings.\nnothing to move: host_packages is gone\nDone. Start the server again: its migrations finish the upgrade.\n").to_stdout
  end

  def check
    Rake::Task["packages:check_snapshots"].reenable
    Rake::Task["packages:check_snapshots"].invoke
  end

  it "says every reference is sound, or lists the problems and exits non-zero" do
    host = enrolled_host.first
    report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
    expect { check }.to output("Package store: every reference is sound.\n").to_stdout
    HostPackageSet.where(host_id: host.id).update_all(package_set_id: nil)
    expect { check }.to raise_error(SystemExit).and output("1 dpkg hosts with no package set\nPackage store: 1 problems.\n").to_stdout
  end
end
