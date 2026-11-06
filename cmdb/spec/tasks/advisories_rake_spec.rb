require "rails_helper"
require "rake"

# bin/rails advisories:import, advisories:refresh, and advisories:status (P2-S10, P2-S13).
RSpec.describe "advisories rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "advisories:import" } }

  def run(task, env = {})
    Rake::Task[task].reenable
    original = env.keys.to_h { |key| [ key, ENV[key] ] }
    env.each { |key, value| ENV[key] = value }
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
    original&.each { |key, value| ENV[key] = value }
  end

  it "imports a directory, printing the counts and each malformed record, audited with the system actor" do
    output = run("advisories:import", "FILE" => AdvisoryHelpers::OSV_FIXTURES.to_s)
    expect(output).to include("osv: 4 records, 2 added, 0 updated, 0 unchanged, 0 older than stored, 1 for other ecosystems, 0 withdrawn, 1 malformed.",
                              "2 reference URLs were not http or https and were dropped.", "  malformed: malformed.json is not valid JSON")
    expect(AdvisoryImport.sole).to have_attributes(origin: "file", full: false)
    expect(AuditEntry.sole).to have_attributes(action: "advisory.imported", actor_type: "system")
  end

  it "marks a complete archive as full with FULL=1, and lists a malformed record's id" do
    stub_const("Advisories::Import::PROBLEM_LIMIT", 1)
    zip = osv_zip("a.json" => osv_record(id: "DSA-1-1"), "b.json" => osv_record(id: "DSA-2-1", package: "Bad"), "c.json" => "x")
    output = run("advisories:import", "FILE" => zip.to_s, "FULL" => "1")
    expect(output).to include("  malformed: b.json (DSA-2-1) has affected[0] with an invalid package name", "(only the first 1 are listed)")
    expect(AdvisoryImport.sole.full).to be(true)
  end

  it "imports nothing from unreadable input, records the failure, and explains usage" do
    expect { expect { run("advisories:import", "FILE" => "/nonexistent/all.zip") }.to output(/Nothing imported: all.zip is not a file or directory/).to_stderr }
      .to raise_error(SystemExit)
    expect(AdvisoryImport.sole).to have_attributes(state: "failed", reason: "all.zip is not a file or directory")
    expect { expect { run("advisories:import", "FILE" => nil) }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
  end

  describe "refresh" do
    around do |example|
      saved = Advisories.config.feed_url
      Advisories.config.feed_url = "https://advisories.example.org/all.zip"
      example.run
    ensure
      Advisories.config.feed_url = saved
    end

    it "refreshes from the feed now, and says when the feed has not changed" do
      stub_request(:get, "https://advisories.example.org/all.zip").to_return(status: 200, body: osv_zip("a.json" => osv_record(id: "DSA-1-1")).binread, headers: { "ETag" => "x" })
      expect(run("advisories:refresh")).to include("advisories.example.org/all.zip: 1 records, 1 added")
      stub_request(:get, "https://advisories.example.org/all.zip").to_return(status: 304)
      expect(run("advisories:refresh")).to eq("advisories.example.org/all.zip: not modified since the last refresh.\n")
    end

    it "says why a refresh failed, and when no feed is configured" do
      stub_request(:get, "https://advisories.example.org/all.zip").to_return(status: 404)
      expect { expect { run("advisories:refresh") }.to output(/Refresh failed: the advisory feed at advisories.example.org answered HTTP 404/).to_stderr }.to raise_error(SystemExit)
      Advisories.config.feed_url = nil
      expect(run("advisories:refresh")).to include("No feed is configured")
    end
  end

  it "shows each ecosystem's freshness and the last import" do
    expect(run("advisories:status")).to eq("Debian:13: never refreshed (older than 48 hours), 0 advisories\n")
    travel_to(Time.utc(2026, 11, 6, 12)) { import_advisories(osv_record(id: "DSA-1-1"), full: true, source: "all.zip") }
    travel_to(Time.utc(2026, 11, 6, 13)) do
      Advisories::Import.record_failure(origin: "feed", source: "example.org/all.zip", reason: "the advisory feed at example.org answered HTTP 500")
      expect(run("advisories:status")).to eq("Debian:13: last updated 2026-11-06T12:00:00Z, 1 advisories\n" \
                                              "Last import: failed 2026-11-06T13:00:00Z from example.org/all.zip: the advisory feed at example.org answered HTTP 500\n")
    end
  end
end
