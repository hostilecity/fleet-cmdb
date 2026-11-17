require "rails_helper"
require "rake"

# bin/rails packages:check_snapshots (#196, ADR 0028): the package store's references, checked by hand.
RSpec.describe "packages rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "packages:check_snapshots" } }

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
