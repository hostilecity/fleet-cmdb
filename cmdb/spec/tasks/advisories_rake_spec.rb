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

  # Owner decision on #129: a full import by hand is guarded like the feed, and needs ALLOW_WITHDRAWALS naming the
  # counts to withdraw more than the thresholds allow.
  describe "the withdrawal guard" do
    before { import_advisories(*(1..5).map { |i| osv_record(id: "DSA-#{i}-1") }, full: true) }

    let(:zip) { osv_zip("a.json" => osv_record(id: "DSA-1-1")) }

    it "refuses a full import that would withdraw too many, with the counts and the exact allowance, recording and auditing them" do
      expect { expect { run("advisories:import", "FILE" => zip.to_s, "FULL" => "1") }.to output(
        %r{Nothing imported: this full import would mark advisories withdrawn.*\n  Debian:13: 4 of 5 current advisories \(1 records in the import\)\nIf that is right, run it again with ALLOW_WITHDRAWALS=Debian:13:4 bin/rails advisories:import FILE=#{Regexp.escape(zip.to_s)} FULL=1}
      ).to_stderr }.to raise_error(SystemExit)
      refused = AdvisoryImport.order(:id).last
      expect(refused).to have_attributes(state: "held_back", full: true)
      expect(refused.counts["would_withdraw"]).to eq("Debian:13" => { "withdraw" => 4, "current" => 5, "records" => 1 })
      expect(AuditEntry.where(action: "advisory.import_held_back").sole.changeset["would_withdraw"]).to be_present
      expect(Advisory.current.count).to eq(5)
    end

    it "imports with an allowance that covers the counts, and refuses one that does not or cannot be read" do
      expect { expect { run("advisories:import", "FILE" => zip.to_s, "FULL" => "1", "ALLOW_WITHDRAWALS" => "Debian:13:3") }.to output(/ALLOW_WITHDRAWALS=Debian:13:4/).to_stderr }
        .to raise_error(SystemExit)
      expect { expect { run("advisories:import", "FILE" => zip.to_s, "FULL" => "1", "ALLOW_WITHDRAWALS" => "Debian:13") }.to output(/must be ecosystem:count pairs/).to_stderr }
        .to raise_error(SystemExit)
      expect(Advisory.current.count).to eq(5)

      output = run("advisories:import", "FILE" => zip.to_s, "FULL" => "1", "ALLOW_WITHDRAWALS" => "Debian:13:4, Other:1:2")
      expect(output).to include("4 withdrawn")
      expect(Advisory.current.pluck(:advisory_id)).to eq([ "DSA-1-1" ])
    end

    it "parses an allowance whose ecosystem name has colons in it" do
      expect(AdvisoriesTask.allowance("Debian:13:41,Some:Distro:9:3")).to eq("Debian:13" => 41, "Some:Distro:9" => 3)
      expect(AdvisoriesTask.allowance(nil)).to eq({})
    end
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

    it "refuses a refresh that would withdraw too many advisories with the counts, then imports it with ALLOW_WITHDRAWALS (review of #129)" do
      import_advisories(*(1..5).map { |i| osv_record(id: "DSA-#{i}-1") }, full: true, origin: "feed", source: "advisories.example.org/all.zip")
      stub_request(:get, "https://advisories.example.org/all.zip").to_return(status: 200, body: osv_zip("a.json" => osv_record(id: "DSA-1-1")).binread)
      expect { expect { run("advisories:refresh") }.to output(/Debian:13: 4 of 5 current advisories.*ALLOW_WITHDRAWALS=Debian:13:4 bin\/rails advisories:refresh/m).to_stderr }
        .to raise_error(SystemExit)
      expect(Advisory.current.count).to eq(5)
      expect(run("advisories:refresh", "ALLOW_WITHDRAWALS" => "Debian:13:4")).to include("4 withdrawn")
      expect(Advisory.current.count).to eq(1)
    end

    it "says why a refresh failed, and when no feed is configured" do
      stub_request(:get, "https://advisories.example.org/all.zip").to_return(status: 404)
      expect { expect { run("advisories:refresh") }.to output(/Refresh failed: the advisory feed at advisories.example.org answered HTTP 404/).to_stderr }.to raise_error(SystemExit)
      # recorded and audited like the job's last attempt, so advisories:status shows it (review of #103)
      expect(AdvisoryImport.sole).to have_attributes(state: "failed", origin: "feed", reason: "the advisory feed at advisories.example.org answered HTTP 404")
      expect(AuditEntry.sole.action).to eq("advisory.import_failed")
      Advisories.config.feed_url = nil
      expect(run("advisories:refresh")).to include("No feed is configured")
    end

    it "is not held back by a manual refresh's cool-down, and starts one itself (P2-S15)" do
      stub_request(:get, "https://advisories.example.org/all.zip").to_return(status: 200, body: osv_zip("a.json" => osv_record(id: "DSA-1-1")).binread)
      operator = create(:operator)
      expect(Advisories::ManualRefresh.request!(actor: operator)).to be_accepted
      expect(run("advisories:refresh")).to include("1 records, 1 added")
      expect(AdvisoryRefreshAttempt.order(:id).pluck(:kind)).to eq(%w[manual task])
      task_started = AdvisoryRefreshAttempt.order(:id).last.started_at
      expect(Advisories::ManualRefresh.request!(actor: operator, now: task_started + 4.minutes))
        .to have_attributes(accepted?: false, next_allowed_at: task_started + 5.minutes)
    end
  end

  it "shows each ecosystem's freshness and the last import, then each release's Debian triage (P2-S16)" do
    never = %w[bookworm forky sid trixie].map { |r| "Debian triage, #{r}: never imported (older than 48 hours), 0 entries\n" }.join
    expect(run("advisories:status")).to eq("Debian:13: never refreshed (older than 48 hours), 0 advisories\n#{never}")
    travel_to(Time.utc(2026, 11, 6, 12)) do
      import_advisories(osv_record(id: "DSA-1-1"), full: true, source: "all.zip")
      import_triage(tracker_document("curl" => { "CVE-2026-0001" => { "trixie" => tracker_release } }))
    end
    travel_to(Time.utc(2026, 11, 6, 13)) do
      Advisories::Import.record_failure(origin: "feed", source: "example.org/all.zip", reason: "the advisory feed at example.org answered HTTP 500")
      expect(run("advisories:status")).to eq("Debian:13: last updated 2026-11-06T12:00:00Z, 1 advisories\n" \
                                              "Last import: failed 2026-11-06T13:00:00Z from example.org/all.zip: the advisory feed at example.org answered HTTP 500\n" \
                                              "Debian triage, bookworm: last updated 2026-11-06T12:00:00Z, 0 entries\n" \
                                              "Debian triage, forky: last updated 2026-11-06T12:00:00Z, 0 entries\n" \
                                              "Debian triage, sid: last updated 2026-11-06T12:00:00Z, 0 entries\n" \
                                              "Debian triage, trixie: last updated 2026-11-06T12:00:00Z, 1 entries\n")
    end
  end

  # P2-S16: Debian's triage, by hand (a server without internet access) or from the tracker now.
  describe "triage_import and triage_refresh" do
    let(:sample) { DebianTrackerHelpers::FIXTURES.join("sample.json").to_s }
    let(:url) { "https://security-tracker.example.org/tracker/data/json" }

    around do |example|
      saved = DebianTriage.config.tracker_url
      DebianTriage.config.tracker_url = url
      example.run
    ensure
      DebianTriage.config.tracker_url = saved
    end

    it "imports a file, printing the counts per release and each malformed entry, audited with the system actor" do
      output = run("advisories:triage_import", "FILE" => sample)
      expect(output).to include("sample.json: 3 source packages, 5 entries (1 not CVE ids), 3 malformed, 1 for releases not in the table.",
                                "  trixie: 3 entries in the file, 0 stored before, 0 dropped, replaced",
                                "  malformed: openssl CVE-2026-90012 is not an object with a releases object", "  malformed: Not A Package is not a valid source package name")
      expect(TriageImport.sole).to have_attributes(origin: "file", source: "sample.json", state: "succeeded")
      expect(AuditEntry.sole).to have_attributes(action: "advisory.triage_imported", actor_type: "system")
    end

    it "holds back a truncated file with the counts and the exact allowance, then imports it with ALLOW_DROPS" do
      run("advisories:triage_import", "FILE" => sample)
      empty = tracker_file("{}").to_s
      expect { expect { run("advisories:triage_import", "FILE" => empty) }.to output(
        /Held back: the document would drop 1 of 1 stored bookworm entries.*\nIf that is right, run it again with ALLOW_DROPS=bookworm:1,forky:1,sid:1,trixie:3 bin\/rails advisories:triage_import FILE=#{Regexp.escape(empty)}/m
      ).to_stderr }.to raise_error(SystemExit)
      expect(TriageEntry.count).to eq(6)
      expect { expect { run("advisories:triage_import", "FILE" => empty, "ALLOW_DROPS" => "trixie") }.to output(/ALLOW_DROPS must be release:count pairs separated by commas, such as trixie:120/).to_stderr }
        .to raise_error(SystemExit)
      expect(run("advisories:triage_import", "FILE" => empty, "ALLOW_DROPS" => "bookworm:1,forky:1,sid:1,trixie:3")).to include("trixie: 0 entries in the file, 3 stored before, 3 dropped, replaced")
      expect(TriageEntry.count).to eq(0)
    end

    it "deletes a release taken out of the table and says so", triage_releases: { [ "debian", "13" ] => "trixie" } do
      TriageEntry.create!(tracker: "debian", release: "bookworm", package: "curl", cve_id: "CVE-2026-0001", status: "open")
      expect(run("advisories:triage_import", "FILE" => sample)).to include("  bookworm: no longer in the release table, 1 entries deleted")
    end

    it "records an unreadable file as failed, and explains usage" do
      expect { expect { run("advisories:triage_import", "FILE" => "/nonexistent/json") }.to output(/Nothing imported: json is not a file/).to_stderr }.to raise_error(SystemExit)
      expect(TriageImport.sole).to have_attributes(state: "failed", origin: "file", reason: "json is not a file")
      expect { expect { run("advisories:triage_import", "FILE" => nil) }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
    end

    it "refreshes from the tracker now, says when it has not changed, why it failed, and when it is turned off" do
      clean = tracker_document("curl" => { "CVE-2026-0001" => { "trixie" => tracker_release } }).to_json
      stub_request(:get, url).to_return(status: 200, body: clean, headers: { "ETag" => '"t1"' })
      expect(run("advisories:triage_refresh")).to include("security-tracker.example.org/tracker/data/json: 1 source packages, 1 entries")
      stub_request(:get, url).to_return(status: 304)
      expect(run("advisories:triage_refresh")).to eq("security-tracker.example.org/tracker/data/json: not modified since the last refresh.\n")
      stub_request(:get, url).to_return(status: 404)
      expect { expect { run("advisories:triage_refresh") }.to output(/Refresh failed: the Debian Security Tracker at security-tracker.example.org answered HTTP 404/).to_stderr }
        .to raise_error(SystemExit)
      expect(TriageImport.order(:id).last).to have_attributes(state: "failed", origin: "feed")
      DebianTriage.config.tracker_url = nil
      expect(run("advisories:triage_refresh")).to include("No Debian Security Tracker is configured")
    end
  end
end

RSpec.describe "vulnerabilities rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "vulnerabilities:match" } }

  it "matches every host in the fleet now and prints the outcome" do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    debian_host
    enrolled_host
    import_advisories(osv_record(id: "DSA-1-1"))
    Rake::Task["vulnerabilities:match"].reenable
    expect { Rake::Task["vulnerabilities:match"].invoke }
      .to output("1 hosts evaluated, 1 not evaluated; 1 findings opened, 0 reopened, 0 resolved.\n").to_stdout
  end
end
