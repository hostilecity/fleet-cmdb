require "rails_helper"
require "rake"

RSpec.describe "backup:verify_restore (P1-O01)" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "backup:verify_restore" } }

  def run(env = {})
    Rake::Task["backup:verify_restore"].reenable
    env.each { |key, value| ENV[key] = value }
    output = StringIO.new
    $stdout = output
    Rake::Task["backup:verify_restore"].invoke
    output.string
  ensure
    $stdout = STDOUT
    env.each_key { |key| ENV.delete(key) }
  end

  before do
    trust_release_keys
    create(:host)
    import_release(signed_release(version: "1.0.0"))
  end

  it "prints each check and passes against a restored database, comparing the recorded counts" do
    counts = Pathname(Dir.mktmpdir).join("counts")
    counts.write("hosts=1\naudit_entries=1\nagent_releases=1\nnot a count line\n")

    expect(run("COUNTS" => counts.to_s)).to include("ok   hosts: 1 restored", "Restore drill passed.")
  end

  it "passes without recorded counts" do
    expect(run).to include("Restore drill passed.")
  end

  it "aborts, naming how many checks failed, when the restore is incomplete" do
    counts = Pathname(Dir.mktmpdir).join("counts")
    counts.write("hosts=9\n")

    expect { expect { run("COUNTS" => counts.to_s) }.to output(/Restore drill FAILED: 1 check/).to_stderr }.to raise_error(SystemExit)
  end
end
