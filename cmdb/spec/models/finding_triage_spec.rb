require "rails_helper"

# Debian's triage beside a page of findings (P2-S16), for the views of P2-D08: the join on source package, host
# release, and CVE ids, the "not available" reasons, and a fixed number of queries per page.
RSpec.describe FindingTriage do
  let(:sample) { DebianTrackerHelpers::FIXTURES.join("sample.json") }
  let(:high) { [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" } ] }

  around do |example|
    saved = DebianTriage.config.tracker_url
    DebianTriage.config.tracker_url = "https://security-tracker.example.org/tracker/data/json"
    example.run
  ensure
    DebianTriage.config.tracker_url = saved
  end

  def glibc_host(**) = debian_host(packages: [ [ "libc6", "2.41-12+deb13u4", "glibc" ], [ "libc-bin", "2.41-12+deb13u4", "glibc" ] ], **)

  def match(*hosts) = VulnerabilityMatcher.match!(hosts.map(&:id))

  # The owner's example (2026-11-07): OSV scores CVE-2026-19499 High by its CVSS vector; Debian notes no-DSA, minor
  # issue, for trixie, with a fix planned for the next point release.
  def import_glibc_advisory
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-19499", package: "glibc", fixed: nil, upstream: [ "CVE-2026-19499" ], severity: high), full: true, origin: "feed")
  end

  describe "P2-S16 acceptance" do
    it "keeps CVE-2026-19499 on a trixie host with glibc 2.41-12+deb13u4 open with its OSV severity, with Debian's no-DSA minor issue note available" do
      host = glibc_host
      import_glibc_advisory
      match(host)
      import_triage(sample)
      match(host) # matching again after the import changes nothing either

      findings = VulnerabilityFinding.where(host:).to_a.sort_by(&:package) # in Ruby: the database collation orders "-" differently
      expect(findings.map { |f| [ f.package, f.state, f.advisory.severity ] }).to eq([ [ "libc-bin", "open", "high" ], [ "libc6", "open", "high" ] ])
      triage = described_class.load(findings)
      findings.each do |finding|
        t = triage[finding]
        expect(t).to have_attributes(available?: true, release: "trixie", cve_ids: [ "CVE-2026-19499" ], reason: nil, detail: nil)
        expect(t.entries.sole).to have_attributes(cve_id: "CVE-2026-19499", status: "open", no_dsa: true, no_dsa_note: "Minor issue", no_dsa_reason: nil,
                                                  urgency: nil, next_point_update: true)
      end
      expect(DebianTriage.tracker_url_for(triage[findings.first].entries.sole.cve_id)).to eq("https://security-tracker.debian.org/tracker/CVE-2026-19499")
      expect(VulnerabilityFinding.where(host:).active.count).to eq(2)
    end

    it "says triage is not available when the source is off, failing, or stale, while OSV refreshes and matching go on" do
      host = glibc_host
      import_glibc_advisory
      match(host)
      finding = VulnerabilityFinding.where(host:).first

      # Failing from the start: nothing was ever imported.
      DebianTriage::Import.record_failure(reason: "the Debian Security Tracker at example.org answered HTTP 503", origin: "feed", source: "example.org/json")
      expect(described_class.load([ finding ])[finding]).to have_attributes(available?: false, reason: "never_imported", entries: [],
                                                                            detail: "Debian triage for trixie has not been imported yet; it is imported at the next refresh once an active host reports that release.")

      import_triage(sample)
      travel 49.hours do
        # Stale, while an OSV refresh still imports and matching still runs.
        import_advisories(osv_record(id: "DEBIAN-CVE-2026-19499", package: "glibc", fixed: nil, upstream: [ "CVE-2026-19499" ], severity: high,
                                     modified: "2026-11-01T00:00:00Z"), full: true, origin: "feed")
        expect(match(host)).to have_attributes(evaluated: 1)
        expect(Advisories::Freshness.statuses.sole.stale).to be(false)
        expect(described_class.load([ finding ])[finding]).to have_attributes(reason: "stale", detail: "Debian triage for trixie is older than 48 hours.")

        DebianTriage.config.tracker_url = nil
        expect(described_class.load([ finding ])[finding]).to have_attributes(
          reason: "source_off", detail: "Debian triage is turned off (FLEET_DEBIAN_TRACKER_URL is empty) and no current data has been imported for trixie."
        )
        # Off, with current data imported by hand: available.
        import_triage(sample)
        expect(described_class.load([ finding ])[finding]).to be_available
      end
      expect(finding.reload).to have_attributes(state: "open")
    end
  end

  it "joins a DSA's aliases and upstream ids, and lists each CVE the tracker has" do
    host = glibc_host(packages: [ [ "libc6", "2.41-12+deb13u4", "glibc" ] ])
    import_advisories(osv_record(id: "DSA-9100-1", package: "glibc", fixed: nil, aliases: [ "CVE-2026-90010" ], upstream: [ "CVE-2026-19499", "CVE-2026-99999" ]))
    match(host)
    import_triage(sample)
    finding = VulnerabilityFinding.sole
    t = described_class.load(VulnerabilityFinding.all)[finding]
    expect(t.cve_ids).to eq(%w[CVE-2026-19499 CVE-2026-90010 CVE-2026-99999])
    expect(t.entries.map(&:cve_id)).to eq(%w[CVE-2026-19499 CVE-2026-90010])
  end

  it "says why for a host with no entry, no CVE, or a release outside the table" do
    trixie = glibc_host(packages: [ [ "curl", "8.14.1-2", "curl" ], [ "openssl", "3.5.0-1", "openssl" ] ])
    unmapped = glibc_host(name: "vm-02", hostname: "vm-02.example.lan", os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu" })
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-90020", package: "curl", fixed: nil), osv_record(id: "DSA-9200-1", package: "openssl", fixed: nil))
    match(trixie)
    import_triage(sample)
    triage = described_class.load(VulnerabilityFinding.all)
    by_package = VulnerabilityFinding.all.index_by(&:package)
    expect(triage[by_package["curl"]]).to have_attributes(reason: "no_entry", detail: "The Debian Security Tracker has no entry for this package and CVE in trixie.")
    expect(triage[by_package["openssl"]]).to have_attributes(reason: "no_cve", cve_ids: [])

    finding = VulnerabilityFinding.create!(host: unmapped, advisory: Advisory.first, package: "curl", architecture: "amd64", source: "curl", ecosystem: "Debian:13",
                                           installed_version: "8.14.1-2", state: "open", first_seen_at: Time.current)
    expect(described_class.load([ finding ])[finding]).to have_attributes(release: nil, reason: "unmapped_release",
                                                                          detail: "ubuntu 24.04 has no release in the Debian Security Tracker's release table.")
    finding.host.inventory.destroy!
    expect(described_class.load([ finding.reload ])[finding].detail).to eq("The host's distribution has no release in the Debian Security Tracker's release table.")
  end

  it "maps a host by its release table row, whatever the release, including one with no VERSION_ID" do
    expect(DebianTriage::Releases.for_os("id" => "Debian", "version_id" => "12")).to eq("bookworm")
    expect(DebianTriage::Releases.for_os("id" => "debian", "version_id" => "14")).to eq("forky")
    expect(DebianTriage::Releases.for_os("id" => "debian", "version_id" => nil)).to eq("sid")
    expect(DebianTriage::Releases.for_os("id" => "debian", "version_id" => "")).to eq("sid")
    expect(DebianTriage::Releases.for_os(nil)).to be_nil
    expect(DebianTriage.tracker_url_for("CVE-2026-1 <script>")).to be_nil
  end

  it "loads a page in the same number of queries whatever its size, with no per-finding lookups" do
    small = glibc_host
    import_glibc_advisory
    import_advisories(*(1..40).map { |i| osv_record(id: "DEBIAN-CVE-2026-#{20_000 + i}", package: "glibc", fixed: nil) })
    large = glibc_host(name: "vm-02", hostname: "vm-02.example.lan")
    match(small, large)
    import_triage(sample)
    one = VulnerabilityFinding.where(host: small).limit(1).to_a
    many = VulnerabilityFinding.where(host: [ small, large ]).includes(:advisory).to_a
    expect(many.size).to be > 80
    queries = ->(findings) { count_queries { described_class.load(findings).then { |t| findings.each { |f| t[f] } } } }
    expect(queries.call(one)).to eq(4) # advisory, inventories, freshness, entries
    expect(queries.call(many)).to eq(3) # advisories already loaded
  end
end
