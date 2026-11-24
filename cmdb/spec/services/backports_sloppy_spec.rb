require "rails_helper"

# trixie-backports-sloppy (#304, Ecosystems::BACKPORTS "sloppy", ADR 0011). Debian names every backport
# "~bpo${release}+${build}" for the release it is built for (backports.debian.org/Contribute), so once forky is released
# the sloppy builds of Debian 15's versions carry ~bpo13+ as trixie-backports' builds of forky's do, as
# buster-backports-sloppy's builds from bookworm carried ~bpo10+1 (apache2 2.4.53-2~bpo10+1) and buster-backports' from
# bullseye did. The version order tells them apart (owner decision of 2026-11-23 on PR #309): Debian refuses uploads to
# the old backports suite "with versions greater than in new stable or new stable-security", so a ~bpo13+ build above
# forky's version of its source (the security tracker's "repositories", BackportSourceVersion) is a sloppy one, matched
# against Debian:15 as well; at or below it, against Debian:14 only; with forky's version unknown, against both.
#
# Versions follow Debian's forms: trixie's linux 6.12.48-1, trixie-backports' 7.0.9-1~bpo13+1 (built from forky
# testing), a trixie-backports build of a forky stable update 7.1.3-1+deb14u1~bpo13+1 (as bookworm-backports'
# 7zip 25.00+ds-1+deb13u1~bpo12+1 is of a trixie one), and a trixie-backports-sloppy build 7.6.2-1~bpo13+1. The advisory
# ids DEBIAN-CVE-2027-9xxxx and the forky stable and Debian 15 fixes are made up: neither exists yet.
RSpec.describe "Matching trixie-backports-sloppy builds (#304)" do # rubocop:disable RSpec/DescribeClass
  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  let(:now) { Time.utc(2026, 11, 23, 12) }
  let(:forky_build) { [ "linux-image-7.1.3+deb13-amd64", "7.1.3-1+deb14u1~bpo13+1", "linux-signed-amd64" ] }
  let(:sloppy_build) { [ "linux-image-7.6.2+deb13-amd64", "7.6.2-1~bpo13+1", "linux-signed-amd64" ] }

  # One advisory naming the package in trixie, forky, and Debian 15 (fixed version, nil for no fix, :absent to leave out).
  def record(id, trixie:, forky:, duke:, package: "linux", **extra)
    affected = { "Debian:13" => trixie, "Debian:14" => forky, "Debian:15" => duke }.reject { |_, fixed| fixed == :absent }.map do |ecosystem, fixed|
      osv_record(id:, package:, fixed:, ecosystem:)["affected"].first
    end
    osv_record(id:, **extra).merge("affected" => affected)
  end

  def import_full(*records) = import_advisories(*records, full: true, origin: "feed")

  def match(*hosts, at: now) = VulnerabilityMatcher.match!(hosts.map(&:id), now: at)

  def finding(host, package, advisory_id) = VulnerabilityFinding.with_details.joins(:advisory).find_by(host:, package:, advisories: { advisory_id: })

  it "matches a sloppy build against Debian 15's data once a full import keeps it, as a union, and records the higher fix" do
    forky = debian_host(packages: [ forky_build ])
    sloppy = debian_host(packages: [ sloppy_build ])
    cve = record("DEBIAN-CVE-2027-90001", trixie: "6.12.99-1", forky: "7.1.3-1+deb14u2", duke: "7.6.4-1")

    # Before forky's release OSV has no Debian:15: matched as #274 did. The sloppy build sorts above forky's fix, so
    # forky's data alone misses it.
    import_full(cve.merge("affected" => cve["affected"].first(2)))
    match(forky, sloppy)
    expect(Backports.complete("Debian:13")).to eq([ "Debian:14" ])
    expect(finding(forky, forky_build[0], cve["id"])).to have_attributes(state: "open", from_fixed_version: "7.1.3-1+deb14u2")
    expect(finding(sloppy, sloppy_build[0], cve["id"])).to be_nil

    result = travel(1.hour) { import_full(cve) }
    expect(result.changed_packages["Debian:15"]).to include("linux", "linux-signed-amd64") # every stored backport, the first time
    expect(Backports.complete("Debian:13")).to eq(%w[Debian:14 Debian:15])
    match(forky, sloppy, at: now + 2.hours)
    expect(finding(sloppy, sloppy_build[0], cve["id"])).to have_attributes(state: "open", source: "linux", fixed_version: nil, from_fixed_version: "7.6.4-1", fixable: false)
    # A forky build is affected under both: the higher fix is shown, since the build may be from Debian 15's series.
    expect(finding(forky, forky_build[0], cve["id"])).to have_attributes(state: "open", fixed_version: nil, from_fixed_version: "7.6.4-1")
  end

  it "records no fix when one affected release has none, and never resolves a finding Debian 15 still affects" do
    host = debian_host(packages: [ sloppy_build ])
    import_full(record("DEBIAN-CVE-2027-90002", trixie: "6.12.99-1", forky: nil, duke: "7.6.4-1"),
                record("DEBIAN-CVE-2027-90003", trixie: "6.12.99-1", forky: "7.1.3-1+deb14u2", duke: nil))
    match(host)
    # Under forky's ranges 7.6.2-1~bpo13+1 is affected with no fix: none is recorded.
    expect(finding(host, sloppy_build[0], "DEBIAN-CVE-2027-90002")).to have_attributes(state: "open", from_fixed_version: nil)
    expect(finding(host, sloppy_build[0], "DEBIAN-CVE-2027-90003")).to have_attributes(state: "open", from_fixed_version: nil)
  end

  it "keeps a finding open while Debian 15 has no data for its source, and resolves it once Debian 15's data names it" do
    host = debian_host(packages: [ [ "calibre", "9.6.0+ds-1~bpo13+1", "calibre" ] ])
    import_full(record("DEBIAN-CVE-2027-90004", trixie: nil, forky: nil, duke: :absent, package: "calibre"),
                record("DEBIAN-CVE-2027-90009", trixie: "6.12.99-1", forky: "7.1.3-1", duke: "7.6.4-1")) # Debian:15 data for linux only
    match(host)
    # forky and trixie fix it below the backport; Debian 15, which a sloppy build can come from, has nothing for calibre.
    import_advisories(record("DEBIAN-CVE-2027-90004", trixie: "9.0.0+ds-1+deb13u1", forky: "9.5.0+ds-1", duke: :absent, package: "calibre",
                             modified: "2026-11-01T00:00:00Z"))
    match(host, at: now + 1.hour)
    expect(finding(host, "calibre", "DEBIAN-CVE-2027-90004")).to have_attributes(state: "open", kept: true, fixed_version: nil)

    # Debian 15's data names calibre in another advisory: not in this one, so it is not affected there either.
    import_advisories(record("DEBIAN-CVE-2027-90005", trixie: :absent, forky: :absent, duke: "9.7.0+ds-1", package: "calibre"))
    match(host, at: now + 2.hours)
    expect(finding(host, "calibre", "DEBIAN-CVE-2027-90004")).to have_attributes(state: "resolved", resolution: "fixed")
  end

  it "keeps open a finding only forky's data shows fixed while Debian 15 has nothing for its source, even when trixie's names nothing" do
    host = debian_host(packages: [ [ "calibre", "9.6.0+ds-1~bpo13+1", "calibre" ] ])
    import_full(record("DEBIAN-CVE-2027-90006", trixie: :absent, forky: nil, duke: :absent, package: "calibre"),
                record("DEBIAN-CVE-2027-90009", trixie: "6.12.99-1", forky: "7.1.3-1", duke: "7.6.4-1"))
    match(host)
    expect(finding(host, "calibre", "DEBIAN-CVE-2027-90006")).to have_attributes(state: "open")
    import_advisories(record("DEBIAN-CVE-2027-90006", trixie: :absent, forky: "9.5.0+ds-1", duke: :absent, package: "calibre", modified: "2026-11-01T00:00:00Z"))
    match(host, at: now + 1.hour)
    expect(finding(host, "calibre", "DEBIAN-CVE-2027-90006")).to have_attributes(state: "open", kept: true, source: "calibre")

    ChunkMatch.where(keep_only: true).delete_all # its verdict gone anyway: never resolved on forky's fix alone
    match(host, at: now + 2.hours)
    expect(finding(host, "calibre", "DEBIAN-CVE-2027-90006")).to have_attributes(state: "open")
  end

  # The security tracker's forky (and duke) versions of a source, as its JSON document lists them per CVE.
  def tracker_versions(package, forky: nil, duke: nil, cve: "CVE-2027-90100")
    releases = { "trixie" => tracker_release(repositories: { "trixie" => "6.12.99-1" }) }
    releases["forky"] = tracker_release(repositories: forky) if forky
    releases["duke"] = tracker_release(repositories: duke) if duke
    import_triage(tracker_document(package => { cve => releases }))
  end

  describe "the version rule (review of #309, S1)" do
    let(:cve) { record("DEBIAN-CVE-2027-90101", trixie: "6.12.99-1", forky: "7.1.3-1+deb14u3", duke: "7.6.4-1") }
    let(:installed) { [ "linux-image-7.1.3+deb13-amd64", "7.1.3-1+deb14u5~bpo13+1", "linux-signed-amd64" ] }
    let(:running) { [ "linux-image-7.1.2+deb13-amd64", "7.1.2-1~bpo13+1", "linux-signed-amd64" ] }

    it "matches a build at or below forky's version against Debian:14 only, so forky's fix counts and K1 is reached" do
      at_fix = debian_host(packages: [ installed ])
      reboot = debian_host(packages: [ running, installed ]).tap { |h| record_inventory(h, kernel_version: "7.1.2+deb13-amd64") }
      sloppy = debian_host(packages: [ sloppy_build ])
      duke_only = record("DEBIAN-CVE-2027-90108", trixie: :absent, forky: :absent, duke: "7.6.4-1") # code only Debian 15's series has
      import_full(cve, duke_only)

      # forky's version unknown: matched against both, which only adds (the conservative choice).
      match(at_fix, reboot, sloppy)
      expect(finding(at_fix, installed[0], cve["id"])).to have_attributes(state: "open", from_fixed_version: "7.6.4-1")
      expect(finding(at_fix, installed[0], duke_only["id"])).to have_attributes(state: "open")
      expect(VulnerabilityTriage.rule_for(finding(reboot, running[0], cve["id"]).bucket_rule)).not_to eq("K1")

      expect(VulnerabilityMatchJob).to receive(:after_import).with("Debian:15" => [ "linux" ]).and_call_original
      tracker_versions("linux", forky: { "forky" => "7.1.3-1+deb14u4", "forky-security" => "7.1.3-1+deb14u5" }, duke: { "duke" => "7.6.4-1" })
      expect(BackportSourceVersion.of("Debian:14", [ "linux" ])).to eq("linux" => "7.1.3-1+deb14u5") # the highest suite's
      VulnerabilityMatcher.match_again!
      match(at_fix, reboot, sloppy, at: now + 1.hour)
      # 7.1.3-1+deb14u5~bpo13+1 sorts below forky's 7.1.3-1+deb14u5: a trixie-backports build, past forky's fix.
      expect(finding(at_fix, installed[0], cve["id"])).to have_attributes(state: "resolved", resolution: "fixed")
      # Debian 15's advisory is not this build's: neither release it is matched against names it.
      expect(finding(at_fix, installed[0], duke_only["id"])).to have_attributes(state: "resolved", resolution: "not_affected")
      expect(finding(reboot, running[0], cve["id"])).to have_attributes(state: "open", from_fixed_version: "7.1.3-1+deb14u3")
      expect(VulnerabilityTriage.rule_for(finding(reboot, running[0], cve["id"]).bucket_rule)).to eq("K1")
      # 7.6.2-1~bpo13+1 sorts above it: a sloppy build, still matched against Debian 15.
      expect(finding(sloppy, sloppy_build[0], cve["id"])).to have_attributes(state: "open", from_fixed_version: "7.6.4-1")
    end

    it "keeps the stored versions when a document does not name the release, ignores versions dpkg cannot parse, and queues nothing before Debian:15" do
      expect(VulnerabilityMatchJob).not_to receive(:after_import)
      tracker_versions("linux", forky: { "forky" => "7.1.3-1+deb14u5", "forky-security" => "not a version!" })
      tracker_versions("calibre", forky: { "forky" => "bad:version" })
      expect(BackportSourceVersion.pluck(:ecosystem, :package, :version)).to eq([ %w[Debian:14 linux 7.1.3-1+deb14u5] ])
      tracker_versions("linux")
      expect(BackportSourceVersion.count).to eq(1)
      expect(Backports.from_versions("Debian:13", [ "Debian:14" ], [ "linux" ])).to eq({})
      expect(Backports.releases_for("Debian:12", [], [ "linux" ], "1.0-1", {}, PackageVersions.for("dpkg"))).to eq([])
      scheme = PackageVersions.for("dpkg")
      expect(Backports.releases_for("Debian:13", %w[Debian:14 Debian:15], [ "linux" ], "bad:version", { "linux" => "7.1.3-1" }, scheme)).to eq(%w[Debian:14 Debian:15])
    end

    it "resolves a sloppy build's finding as fixed on Debian 15's evidence alone (review N1)" do
      host = debian_host(packages: [ [ "calibre", "9.6.0+ds-1~bpo13+1", "calibre" ] ])
      tracker_versions("calibre", forky: { "forky" => "9.5.0+ds-1" })
      import_full(record("DEBIAN-CVE-2027-90102", trixie: :absent, forky: :absent, duke: nil, package: "calibre"),
                  record("DEBIAN-CVE-2027-90103", trixie: "9.0.0+ds-1+deb13u1", forky: "9.5.0+ds-1", duke: "9.5.0+ds-1", package: "calibre"))
      match(host)
      expect(finding(host, "calibre", "DEBIAN-CVE-2027-90102")).to have_attributes(state: "open")
      import_advisories(record("DEBIAN-CVE-2027-90102", trixie: :absent, forky: :absent, duke: "9.5.9+ds-1", package: "calibre", modified: "2026-11-01T00:00:00Z"))
      match(host, at: now + 1.hour)
      expect(finding(host, "calibre", "DEBIAN-CVE-2027-90102")).to have_attributes(state: "resolved", resolution: "fixed")
    end
  end

  describe "a release that was complete and is then dropped (review of #309, S2)", withdrawal_guard: { share: 1.0, min_records: 0 } do
    let(:duke_only) { record("DEBIAN-CVE-2027-90104", trixie: "6.12.99-1", forky: "7.1.3-1", duke: "7.6.4-1") }
    let(:forky_only) { record("DEBIAN-CVE-2027-90105", trixie: "6.12.99-1", forky: "7.6.9-1", duke: :absent) }
    let(:without) { ->(r, ecosystem) { r.merge("affected" => r["affected"].reject { |a| a["package"]["ecosystem"] == ecosystem }) } }

    it "keeps its last rows, so no finding resolves for its lack, and drops them once an import has that release's data" do
      host = debian_host(packages: [ sloppy_build ])
      import_full(duke_only, forky_only)
      match(host)
      expect(finding(host, sloppy_build[0], duke_only["id"])).to have_attributes(state: "open")
      expect(finding(host, sloppy_build[0], forky_only["id"])).to have_attributes(state: "open")

      # A mirror with neither release: the records are as modified as before, and a newer one is rewritten.
      result = travel(1.hour) { import_full(without.call(without.call(duke_only, "Debian:15"), "Debian:14"), without.call(forky_only.merge("modified" => "2026-11-01T00:00:00Z"), "Debian:14")) }
      expect(result.import.counts).to include("held_entries" => 3, "unchanged" => 1, "updated" => 1)
      expect(result.changed_packages).to eq("Debian:13" => [ "linux" ])
      expect(Backports.statuses("Debian:13").map(&:state)).to eq(%i[dropped dropped])
      match(host, at: now + 2.hours)
      expect(VulnerabilityFinding.where(host:).pluck(:state)).to all(eq("open"))

      # OSV again, with Debian 14 and 15, but this advisory's Debian 15 entry really gone: that one goes.
      other = record("DEBIAN-CVE-2027-90106", trixie: "6.12.99-1", forky: "7.1.3-1", duke: "7.6.4-1")
      result = travel(2.hours) { import_full(without.call(duke_only, "Debian:15"), forky_only.merge("modified" => "2026-11-01T00:00:00Z"), other) }
      expect(result.import.counts).not_to have_key("held_entries")
      expect(result.changed_packages["Debian:15"]).to eq([ "linux" ])
      match(host, at: now + 3.hours)
      expect(finding(host, sloppy_build[0], duke_only["id"])).to have_attributes(state: "resolved")
      expect(finding(host, sloppy_build[0], forky_only["id"])).to have_attributes(state: "open")
    end

    it "takes a partial import's record as it is, and keeps nothing of a withdrawn one" do
      import_full(duke_only, forky_only)
      import_advisories(without.call(duke_only, "Debian:15").merge("modified" => "2026-11-01T00:00:00Z"))
      expect(AdvisoryPackage.where(ecosystem: "Debian:15").count).to eq(0)
      # An archive with no Debian 14 at all: the other record's rows are held, the withdrawn one's are not.
      import_full(without.call(duke_only, "Debian:14"), without.call(forky_only, "Debian:14").merge("modified" => "2026-11-02T00:00:00Z", "withdrawn" => "2026-11-02T00:00:00Z"))
      expect(AdvisoryPackage.joins(:advisory).where(advisories: { advisory_id: duke_only["id"] }).order(:ecosystem).pluck(:ecosystem)).to eq(%w[Debian:13 Debian:14])
      expect(AdvisoryPackage.joins(:advisory).where(advisories: { advisory_id: forky_only["id"] }).pluck(:ecosystem)).to eq([ "Debian:13" ])
    end

    it "lists a source Debian 15 has nothing for only for a backport matched against it" do
      host = debian_host(packages: [ [ "calibre", "9.5.0+ds-1~bpo13+1", "calibre" ], [ "libfoo1", "2.0-1~bpo13+1", "foo" ] ])
      tracker_versions("calibre", forky: { "forky" => "9.5.0+ds-1" })
      import_full(duke_only, record("DEBIAN-CVE-2027-90109", trixie: "1.0-1", forky: "1.0-1", duke: :absent, package: "calibre"))
      match(host)
      backports = HostBackports.new("Debian:13", HostPackageSet.find_by!(host_id: host.id).package_set_id, host_id: host.id)
      expect(backports.uncovered).to eq("Debian:14" => [ "foo" ], "Debian:15" => [ "foo" ]) # calibre is forky-series: not matched against Debian 15
    end
  end

  it "counts a backport's sources as changed only on the first full import that keeps a release (review N1)" do
    debian_host(packages: [ sloppy_build ])
    cve = record("DEBIAN-CVE-2027-90107", trixie: "6.12.99-1", forky: "7.1.3-1", duke: "7.6.4-1")
    expect(import_full(cve).changed_packages.keys).to include("Debian:15")
    again = travel(1.hour) { import_full(cve) }
    expect(again.changed_packages).to eq({})
  end

  describe "the releases' statuses (Backports.statuses)", withdrawal_guard: { share: 1.0, min_records: 0 } do
    let(:trixie_only) { osv_record(id: "DSA-9101-1", package: "openssl", fixed: "3.5.1-1+deb13u1") }
    let(:with_forky) { record("DEBIAN-CVE-2026-64253", trixie: "6.12.95-1", forky: "7.1.3-1", duke: :absent) }

    def statuses = Backports.statuses("Debian:13").index_by(&:from)

    it "says when none has come, when full imports arrive without it, and when it goes stale" do
      expect(statuses.transform_values(&:state)).to eq("Debian:14" => :never, "Debian:15" => :awaited)

      missed = import_full(trixie_only).import # an archive with trixie's data only: forky's never comes from it
      expect(statuses["Debian:14"]).to have_attributes(state: :missing, missing: missed, complete: false, updated_at: nil, stale: true)
      expect(statuses["Debian:14"]).to be_warning
      expect(statuses["Debian:15"]).to have_attributes(state: :awaited, missing: missed)
      expect(statuses["Debian:15"]).not_to be_warning

      kept = travel(1.hour) { import_full(with_forky).import }
      expect(statuses["Debian:14"]).to have_attributes(state: :fresh, missing: nil, import: kept, updated_at: kept.finished_at)
      expect(statuses["Debian:14"]).not_to be_warning

      travel(Advisories.config.max_age + 2.hours) do
        expect(statuses["Debian:14"]).to have_attributes(state: :stale, stale: true, missing: nil)
        missed_again = import_full(trixie_only).import
        expect(statuses["Debian:14"]).to have_attributes(state: :dropped, stale: true, import: kept, missing: missed_again)
        expect(statuses["Debian:14"]).to be_warning
      end
      expect(Backports.statuses("Debian:12")).to eq([])
      expect(Backports.status("Debian:12")).to be_nil
      expect(Backports.complete("Debian:12")).to eq([])
    end

    it "warns for Debian 15 once the tracker lists it and full imports still arrive without it (review N2)" do
      import_full(with_forky)
      expect(statuses["Debian:15"].state).to eq(:awaited)
      tracker_versions("linux", duke: { "duke" => "7.6.4-1" })
      expect(statuses["Debian:15"]).to have_attributes(state: :missing, published: true)
      expect(statuses["Debian:15"]).to be_warning
    end

    it "does not count a partial import, and a sloppy release once kept is fresh and goes stale as the others do" do
      import_advisories(with_forky)
      expect(statuses["Debian:14"].state).to eq(:never)
      import_full(record("DEBIAN-CVE-2027-90009", trixie: "6.12.99-1", forky: "7.1.3-1", duke: "7.6.4-1"))
      expect(statuses.transform_values(&:state)).to eq("Debian:14" => :fresh, "Debian:15" => :fresh)
      travel(Advisories.config.max_age + 1.hour) { expect(statuses["Debian:15"].state).to eq(:stale) }
    end
  end

  it "maps the releases in the table" do
    expect(Ecosystems.backports_releases("Debian:13")).to eq(%w[Debian:14 Debian:15])
    expect(Ecosystems.backports_releases("Debian:12")).to eq([])
    expect(Ecosystems.backports_into("Debian:15")).to eq([ "Debian:13" ])
    expect(Ecosystems.imported).to eq(%w[Debian:13 Debian:14 Debian:15])
    expect([ Ecosystems.sloppy?("Debian:15"), Ecosystems.sloppy?("Debian:14") ]).to eq([ true, false ])
    expect(Ecosystems.display_name("Debian:15")).to eq("Debian 15 (duke)")
    expect(Ecosystems.backport?("Debian:13", sloppy_build[1])).to be(true)
  end
end
