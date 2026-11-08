require "rails_helper"

# Storing the Debian Security Tracker's triage (P2-S16, ADR 0022): only the release table's releases and CVE ids,
# normalised, each release replaced in one transaction, malformed entries skipped and counted, and the truncation
# guard holding back a release the document would drop too many entries of.
RSpec.describe DebianTriage::Import do
  let(:sample) { DebianTrackerHelpers::FIXTURES.join("sample.json") }

  def entry(release, package, cve_id) = TriageEntry.find_by!(tracker: "debian", release:, package:, cve_id:)

  # n CVEs for package in each release given, all open.
  def document(n, releases: %w[trixie], package: "curl", from: 1)
    tracker_document(package => (from...(from + n)).to_h { |i| [ "CVE-2026-#{10_000 + i}", releases.index_with { tracker_release } ] })
  end

  it "stores the mapped releases' entries for CVE ids, normalised, and counts the rest" do
    import = import_triage(sample, source: "sample.json")
    expect(import).to have_attributes(tracker: "debian", origin: "file", source: "sample.json", state: "succeeded", releases: %w[bookworm forky sid trixie])
    expect(import.counts).to include("packages" => 3, "entries" => 5, "other_ids" => 1, "other_releases" => 1, "malformed" => 3, "repeated" => 0,
                                     "removed_releases" => {})
    expect(import.counts["releases"]).to eq("bookworm" => { "stored" => 0, "in_file" => 1, "dropped" => 0, "outcome" => "replaced" },
                                            "forky" => { "stored" => 0, "in_file" => 1, "dropped" => 0, "outcome" => "replaced" },
                                            "sid" => { "stored" => 0, "in_file" => 1, "dropped" => 0, "outcome" => "replaced" },
                                            "trixie" => { "stored" => 0, "in_file" => 3, "dropped" => 0, "outcome" => "replaced" })
    expect(import.problems).to contain_exactly(
      { "package" => "openssl", "id" => "CVE-2026-90011", "problem" => "bookworm: has no status of open, resolved, or undetermined" },
      { "package" => "openssl", "id" => "CVE-2026-90012", "problem" => "is not an object with a releases object" },
      { "package" => "Not A Package", "problem" => "is not a valid source package name" }
    )
    expect(entry("trixie", "glibc", "CVE-2026-19499")).to have_attributes(status: "open", urgency: nil, urgency_raw: "not yet assigned", fixed_version: nil,
                                                                          no_dsa: true, no_dsa_note: "Minor issue", no_dsa_reason: nil, next_point_update: true, scope: "remote")
    expect(entry("bookworm", "glibc", "CVE-2026-19499")).to have_attributes(no_dsa: true, no_dsa_note: "Minor issue", no_dsa_reason: "postponed", next_point_update: false)
    expect(entry("sid", "glibc", "CVE-2026-19499")).to have_attributes(status: "resolved", fixed_version: "2.43-5", no_dsa: false, no_dsa_note: nil)
    expect(entry("trixie", "glibc", "CVE-2026-90010")).to have_attributes(status: "resolved", urgency: "low", urgency_raw: "low*", scope: "local")
    expect(entry("trixie", "openssl", "CVE-2026-90011")).to have_attributes(status: "undetermined", urgency: "high", no_dsa_note: "Not worth a DSA", no_dsa_reason: "ignored")
    expect(TriageEntry.where(cve_id: "TEMP-0000000-ABCDEF")).to be_empty
    expect(TriageEntry.where(release: "bullseye")).to be_empty
    expect(AuditEntry.sole).to have_attributes(action: "advisory.triage_imported", actor_type: "system", target_type: "TriageImport", target_id: import.id)
    expect(AuditEntry.sole.changeset).to include("origin" => "file", "source" => "sample.json", "counts" => import.counts)
  end

  it "skips an entry whose fields are not in the tracker's shape, keeping the rest of the release" do
    import = import_triage(tracker_document("curl" => {
      "CVE-2026-0001" => { "trixie" => tracker_release(fixed_version: 3) }, "CVE-2026-0002" => { "trixie" => tracker_release(urgency: "x" * 65) },
      "CVE-2026-0003" => { "trixie" => tracker_release(nodsa: [ "Minor" ]) }, "CVE-2026-0004" => { "trixie" => "open" },
      "CVE-2026-0005" => { "trixie" => tracker_release(urgency: "", nodsa: "", nodsa_reason: "postponed") }
    }))
    expect(import.problems.map { |p| p["problem"] }).to eq([ "trixie: has a fixed_version that is not a string of at most 256 characters",
                                                             "trixie: has a urgency that is not a string of at most 64 characters",
                                                             "trixie: has a nodsa that is not a string of at most 512 characters", "trixie: is not an object" ])
    expect(TriageEntry.sole).to have_attributes(cve_id: "CVE-2026-0005", urgency: nil, urgency_raw: "", no_dsa: true, no_dsa_note: nil, no_dsa_reason: "postponed")
  end

  it "reports a package whose value could not be read, and lists only the first problems" do
    stub_const("#{described_class}::PROBLEM_LIMIT", 1)
    import = import_triage(%({"curl": [1], "wget": {"x": tru}}))
    expect(import.counts["malformed"]).to eq(2)
    expect(import.problems).to eq([ { "package" => "curl", "problem" => "is not an object" } ])
  end

  it "counts an entry repeated in the document once, keeping the first" do
    import = import_triage(%({"curl": {"CVE-2026-0001": {"releases": {"trixie": {"status": "open"}}}}, "curl": {"CVE-2026-0001": {"releases": {"trixie": {"status": "resolved"}}}}}))
    expect(import.counts["repeated"]).to eq(1)
    expect(TriageEntry.sole.status).to eq("open")
  end

  it "replaces each release's data with the new document's, in batches" do
    stub_const("#{described_class}::BATCH", 3)
    import_triage(document(10, releases: %w[trixie bookworm]))
    import = import_triage(document(10, releases: %w[trixie bookworm], from: 2))
    expect(import.counts["releases"]["trixie"]).to eq("stored" => 10, "in_file" => 10, "dropped" => 1, "outcome" => "replaced")
    expect(TriageEntry.where(release: "trixie").pluck(:cve_id)).to match_array((2..11).map { |i| "CVE-2026-#{10_000 + i}" })
    expect(TriageEntry.count).to eq(20)
  end

  it "stores nothing from a document that cannot be read" do
    import_triage(document(3))
    expect { import_triage('{"curl": {') }.to raise_error(Advisories::Unreadable)
    expect(TriageEntry.count).to eq(3)
    expect(TriageImport.count).to eq(1)
  end

  it "records a failure, audited" do
    import = described_class.record_failure(reason: "the Debian Security Tracker at example.org answered HTTP 503", origin: "feed", source: "example.org/json")
    expect(import).to have_attributes(state: "failed", releases: [], reason: "the Debian Security Tracker at example.org answered HTTP 503")
    expect(AuditEntry.sole).to have_attributes(action: "advisory.triage_import_failed", actor_type: "system")
  end

  it "deletes a release taken out of the release table", triage_releases: { [ "debian", "13" ] => "trixie" } do
    hosts_on("12", "13")
    TriageEntry.create!(tracker: "debian", release: "bookworm", package: "curl", cve_id: "CVE-2026-0001", status: "open")
    import = import_triage(document(2), releases: nil)
    expect(import).to have_attributes(state: "succeeded", releases: [ "trixie" ])
    expect(import.counts["removed_releases"]).to eq("bookworm" => 1)
    expect(TriageEntry.distinct.pluck(:release)).to eq([ "trixie" ])
  end

  # Owner decision on #135: only the releases active hosts report are imported (as the spec says), through the
  # release table.
  describe "the releases hosts report" do
    def import_for_hosts(document = sample) = import_triage(document, releases: nil)

    it "keeps only the releases active hosts report, counting the others" do
      trixie, bookworm = hosts_on("13", "12")
      bookworm.retire!(actor: Audit::SYSTEM)
      import = import_for_hosts
      expect(trixie).to be_present
      expect(import).to have_attributes(state: "succeeded", releases: [ "trixie" ], removed_releases: %w[bookworm forky sid])
      expect(import.counts["releases"].keys).to eq([ "trixie" ])
      expect(import.counts["other_releases"]).to eq(5) # bullseye, and glibc's bookworm, forky, and sid
      expect(TriageEntry.distinct.pluck(:release)).to eq([ "trixie" ])
    end

    it "drops a release no active host reports any more without the truncation guard, and says so in the audit entry" do
      _trixie, bookworm = hosts_on("13", "12")
      expect(import_for_hosts.releases).to eq(%w[bookworm trixie])
      bookworm.retire!(actor: Audit::SYSTEM)
      import = import_for_hosts
      expect(import).to have_attributes(state: "succeeded", releases: [ "trixie" ], reason: nil)
      expect(import.counts["removed_releases"]).to eq("bookworm" => 1)
      expect(TriageEntry.where(release: "bookworm")).to be_empty
      expect(AuditEntry.where(action: "advisory.triage_imported").order(:id).last.changeset["removed"])
        .to eq("dropped bookworm (1 entries: no active host reports it); dropping a release the fleet does not use is expected, so the truncation guard does not apply")
    end

    it "imports a release a host starts reporting at the next import, and says it is not imported yet until then" do
      hosts_on("13")
      import_for_hosts
      statuses = -> { DebianTriage::Freshness.statuses.index_by(&:release) }
      expect(statuses.call["bookworm"]).to be_never
      bookworm = hosts_on("12").first
      expect(statuses.call["bookworm"]).to be_never
      expect(import_for_hosts.releases).to eq(%w[bookworm trixie])
      expect(statuses.call["bookworm"]).not_to be_never
      expect(TriageEntry.where(release: "bookworm").count).to eq(1)

      # Dropped, then reported again: not imported yet, rather than fresh with nothing in it.
      travel 1.minute do
        bookworm.retire!(actor: Audit::SYSTEM)
        import_for_hosts
      end
      travel 2.minutes do
        hosts_on("12")
        expect(statuses.call["bookworm"]).to be_never
      end
    end

    it "imports nothing with no active host, without reading the document, and says so" do
      import_triage(sample)
      reader = instance_double(DebianTriage::Reader)
      import = described_class.new(origin: "file", source: "json").call(reader)
      expect(import).to have_attributes(state: "succeeded", releases: [], removed_releases: %w[bookworm forky sid trixie],
                                        reason: "no active host reports a release in the release table (config/triage_releases.yml), so nothing was imported")
      expect(import.counts).to include("no_hosts" => true, "removed_releases" => { "bookworm" => 1, "forky" => 1, "sid" => 1, "trixie" => 3 })
      expect(TriageEntry.count).to eq(0)
      expect(AuditEntry.order(:id).last).to have_attributes(action: "advisory.triage_imported")
    end
  end

  # P2-S16 acceptance: a file missing most of a release's entries keeps the previous data and is recorded as held
  # back with the counts (as the OSV withdrawal guard, review of #131).
  describe "the truncation guard" do
    before { import_triage(document(20, releases: %w[trixie bookworm])) }

    it "holds back a release the document would drop more than 10% of, storing the others, audited with the counts" do
      truncated = tracker_document("curl" => (1..20).to_h { |i| [ "CVE-2026-#{10_000 + i}", (i <= 3 ? { "trixie" => tracker_release } : {}).merge("bookworm" => tracker_release(status: "resolved")) ] })
      import = import_triage(truncated)
      expect(import).to have_attributes(state: "held_back", releases: %w[bookworm forky sid],
                                        reason: "the document would drop 17 of 20 stored trixie entries, so that release keeps its previous data")
      expect(import.counts["releases"]["trixie"]).to eq("stored" => 20, "in_file" => 3, "dropped" => 17, "outcome" => "held_back")
      expect(TriageEntry.where(release: "trixie").count).to eq(20)
      expect(TriageEntry.where(release: "trixie").distinct.pluck(:status)).to eq([ "open" ])
      expect(TriageEntry.where(release: "bookworm").distinct.pluck(:status)).to eq([ "resolved" ])
      audit = AuditEntry.where(action: "advisory.triage_import_held_back").sole
      expect(audit.changeset["counts"]["releases"]["trixie"]).to include("dropped" => 17)
    end

    it "holds back every release a document lacks, and names them all" do
      import = import_triage(document(1, package: "wget"))
      expect(import.reason).to eq("the document would drop 20 of 20 stored bookworm entries and 20 of 20 stored trixie entries, so those releases keep their previous data")
    end

    it "allows up to the threshold" do
      expect(import_triage(document(18, releases: %w[trixie bookworm], from: 3)).state).to eq("succeeded")
    end

    it "uses the configured share", withdrawal_guard: { share: 0.9 } do
      expect(import_triage(document(3, releases: %w[trixie bookworm])).state).to eq("succeeded")
    end

    it "lets an operator's confirmation drop at most the confirmed counts" do
      expect(import_triage(document(3, releases: %w[trixie bookworm]), allowed_drops: { "trixie" => 17, "bookworm" => 17 }).state).to eq("succeeded")
      import_triage(document(20, releases: %w[trixie bookworm]))
      import = import_triage(document(3, releases: %w[trixie bookworm]), allowed_drops: { trixie: 17 })
      expect(import.counts["releases"].transform_values { |c| c["outcome"] }).to include("trixie" => "replaced", "bookworm" => "held_back")
    end
  end

  # ADR 0022, item 3: triage is an annotation. Importing it changes no finding, advisory, evaluation, or count, and
  # starts no matching.
  it "leaves findings, advisories, and counts unchanged" do
    host = debian_host(packages: [ [ "libc6", "2.41-12+deb13u4", "glibc" ] ])
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-19499", package: "glibc", fixed: nil, upstream: [ "CVE-2026-19499" ],
                                 severity: [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" } ]), full: true, origin: "feed")
    VulnerabilityMatcher.match!([ host.id ])
    snapshot = -> { [ VulnerabilityFinding.order(:id).map(&:attributes), Advisory.order(:id).map(&:attributes), HostVulnerabilityEvaluation.order(:id).map(&:attributes),
                      FleetCompliance.totals, FleetCompliance.rows_for(FleetCompliance.per_host.to_a).transform_values { |row| row.to_h.except(:host) } ] }
    before = snapshot.call
    expect { import_triage(sample) }.not_to have_enqueued_job
    expect(snapshot.call).to eq(before)
    expect(VulnerabilityFinding.sole).to have_attributes(state: "open")
  end
end
