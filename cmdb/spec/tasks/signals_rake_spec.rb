require "rails_helper"
require "rake"

# bin/rails signals:kev_import, kev_refresh, kev_clear, epss_import, and epss_refresh (VT-S02, VT-S03): the offline
# imports for a server without internet access, the refreshes run once, and clearing KEV data, all audited.
RSpec.describe "signals rake tasks" do
  include ActiveJob::TestHelper

  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "signals:kev_import" } }

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

  around do |example|
    saved = Signals.config.to_h.slice(:kev_url, :epss_url)
    Signals.config.kev_url = "https://kev.example.org/kev.json"
    Signals.config.epss_url = "https://epss.example.org/epss.csv.gz"
    example.run
  ensure
    Signals.config.kev_url, Signals.config.epss_url = saved.values_at(:kev_url, :epss_url)
  end

  it "imports a KEV file, printing the counts and malformed entries, audited with the system actor" do
    path = kev_file(*(1..10).map { |i| format("CVE-2026-%04d", i) }, kev_vulnerability("CVE-2026-0099", dateAdded: "x"))
    output = run("signals:kev_import", "FILE" => path.to_s)
    expect(output).to include("known_exploited_vulnerabilities.json (2026.11.19): in file 10, stored 0, added 10, removed 0, malformed 1",
                              "  malformed: index 10, id CVE-2026-0099, problem has no valid dateAdded")
    expect(SignalImport.sole).to have_attributes(origin: "file", state: "succeeded")
    expect(AuditEntry.sole).to have_attributes(action: "signal.kev_imported", actor_type: "system")
  end

  it "holds back a KEV file that drops too many entries with the exact allowance, then imports it with ALLOW_DROPS" do
    import_kev(kev_file(*(1..20).map { |i| format("CVE-2026-%04d", i) }))
    path = kev_file("CVE-2026-0001")
    expect { run("signals:kev_import", "FILE" => path.to_s) }
      .to raise_error(SystemExit).and output(/Held back: the catalog would remove 19 of 20 stored entries.*\nIf that is right, run it again with ALLOW_DROPS=19 bin\/rails signals:kev_import FILE=/).to_stderr
    run("signals:kev_import", "FILE" => path.to_s, "ALLOW_DROPS" => "19")
    expect(KevEntry.count).to eq(1)
    expect { run("signals:kev_import", "FILE" => path.to_s, "ALLOW_DROPS" => "many") }.to raise_error(SystemExit).and output(/ALLOW_DROPS must be a whole number/).to_stderr
  end

  it "records an unreadable file as a failed import and explains usage" do
    expect { run("signals:kev_import", "FILE" => "/nonexistent/kev.json") }.to raise_error(SystemExit).and output(/Nothing imported: kev.json is not a file/).to_stderr
    expect(SignalImport.sole).to have_attributes(state: "failed", origin: "file")
    expect { run("signals:kev_import", "FILE" => "") }.to raise_error(SystemExit).and output(/Usage: bin\/rails signals:kev_import FILE=/).to_stderr
    expect { run("signals:epss_import", "FILE" => "") }.to raise_error(SystemExit).and output(/Usage: bin\/rails signals:epss_import FILE=/).to_stderr
  end

  it "imports an EPSS file, and refuses an older one, recording why" do
    advisory_for("CVE-2026-0001")
    output = run("signals:epss_import", "FILE" => epss_file([ %w[CVE-2026-0001 0.2 0.9] ], date: "2026-11-19").to_s)
    expect(output).to include("epss_scores-current.csv.gz (v2025.03.14, scores of 2026-11-19): rows 1, valid 1, malformed 0, repeated 0, kept 1")
    expect { run("signals:epss_import", "FILE" => epss_file([ %w[CVE-2026-0001 0.2 0.9] ], date: "2026-11-01").to_s) }
      .to raise_error(SystemExit).and output(/Nothing imported: the file's scores are of 2026-11-01/).to_stderr
    expect(SignalImport.order(:id).last).to have_attributes(state: "failed", signal: "epss")
  end

  it "refreshes once, printing the outcome, not modified, a failure, or that the source is off" do
    stub_request(:get, "https://kev.example.org/kev.json").to_return(status: 200, body: kev_file("CVE-2026-0001").read, headers: { "ETag" => '"a"' })
    expect(run("signals:kev_refresh")).to include("kev.example.org/kev.json (2026.11.19): in file 1")
    stub_request(:get, "https://kev.example.org/kev.json").with(headers: { "If-None-Match" => '"a"' }).to_return(status: 304)
    expect(run("signals:kev_refresh")).to eq("kev.example.org/kev.json: not modified since the last refresh.\n")
    stub_request(:get, "https://epss.example.org/epss.csv.gz").to_return(status: 404)
    expect { run("signals:epss_refresh") }.to raise_error(SystemExit).and output(/Refresh failed: the FIRST EPSS download at epss.example.org answered HTTP 404/).to_stderr
    expect(SignalImport.epss.sole).to have_attributes(state: "failed")
    Signals.config.epss_url = nil
    expect(run("signals:epss_refresh")).to eq("No EPSS source is configured (FLEET_EPSS_URL is empty).\n")
  end

  it "prints the refusal when a refresh finds an older EPSS file" do
    advisory_for("CVE-2026-0001")
    travel_to(Time.utc(2026, 11, 30)) { import_epss(epss_file([ %w[CVE-2026-0001 0.2 0.9] ], date: "2026-11-30")) }
    stub_request(:get, "https://epss.example.org/epss.csv.gz").to_return(status: 200, body: epss_file([ %w[CVE-2026-0001 0.2 0.9] ]).binread)
    expect { run("signals:epss_refresh") }.to raise_error(SystemExit).and output(/Nothing imported: the file's scores are of 2026-11-19, older than/).to_stderr
  end

  it "clears KEV data only with CONFIRM=1, saying that rules N1 and I5 stop applying" do
    import_kev(kev_file("CVE-2026-0001"))
    expect { run("signals:kev_clear") }.to raise_error(SystemExit).and output(/Run it again with CONFIRM=1/).to_stderr
    expect(KevEntry.count).to eq(1)
    expect(run("signals:kev_clear", "CONFIRM" => "1")).to include("1 KEV entries deleted. KEV entries deleted: rule N1 (known exploited) and rule I5")
    expect(KevEntry.count).to eq(0)
    expect(AuditEntry.where(action: "signal.kev_cleared").sole).to have_attributes(actor_type: "system")
  end

  it "resets EPSS only with CONFIRM=1, so the next file imports whatever its date (review of #269)" do
    advisory_for("CVE-2026-0001")
    import_epss(epss_file([ %w[CVE-2026-0001 0.2 0.9] ]))
    expect { run("signals:epss_reset") }.to raise_error(SystemExit).and output(/bin\/rails signals:epss_reset CONFIRM=1/).to_stderr
    expect(EpssScore.count).to eq(1)
    expect(run("signals:epss_reset", "CONFIRM" => "1")).to include("1 EPSS scores deleted. EPSS scores deleted: rule N2 stops applying")
    expect(EpssScore.count).to eq(0)
  end
end
