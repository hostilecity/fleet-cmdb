require "rails_helper"

# Backports are matched against the release they are built from (#274, Ecosystems::BACKPORTS, Backports; the owner chose
# option 3 on 2026-11-23). Package names and versions are Debian's: trixie's kernel linux 6.12.48-1
# (linux-image-6.12.48+deb13-amd64 from linux-signed-amd64), trixie-backports' linux 7.0.9-1~bpo13+1
# (linux-image-7.0.9+deb13-amd64 from linux-signed-amd64 7.0.9+1~bpo13+1), and trixie-backports' calibre
# 8.16.2+ds+~0.10.5-3~bpo13+1, which OSV lists under Debian:14 for DEBIAN-CVE-2026-26064 (trixie's fix 8.5.0+ds-1+deb13u2).
# The kernel advisories follow Debian's data: DEBIAN-CVE-2025-39748 is fixed in trixie by 6.12.43-1 and in forky by
# 6.16.3-1, as OSV publishes it; CVE-2026-64253 is fixed in trixie by 6.12.95-1 and in forky and sid by 7.1.3-1, as the
# security tracker lists it. DEBIAN-CVE-2026-91xxx are made up, as are the later backport versions (7.1.3, 7.3.4, 9.4.0).
RSpec.describe "Matching backports (#274)" do # rubocop:disable RSpec/DescribeClass
  include ActiveJob::TestHelper

  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  let(:now) { Time.utc(2026, 11, 23, 12) }
  let(:trixie_image) { [ "linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:trixie_meta) { [ "linux-image-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:bpo_image) { [ "linux-image-7.0.9+deb13-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ] }
  let(:bpo_meta) { [ "linux-image-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ] }
  let(:calibre) { [ "calibre", "8.16.2+ds+~0.10.5-3~bpo13+1", "calibre" ] }

  # One advisory naming the package in Debian:13 (trixie's fix) and Debian:14 (forky's); :absent leaves an ecosystem out.
  def record(id, trixie:, forky:, package: "linux", **extra)
    affected = { "Debian:13" => trixie, "Debian:14" => forky }.reject { |_, fixed| fixed == :absent }.map do |ecosystem, fixed|
      osv_record(id:, package:, fixed:, ecosystem:)["affected"].first
    end
    osv_record(id:, **extra).merge("affected" => affected)
  end

  def cve_64253(**) = record("DEBIAN-CVE-2026-64253", trixie: "6.12.95-1", forky: "7.1.3-1", **)
  def cve_39748 = record("DEBIAN-CVE-2025-39748", trixie: "6.12.43-1", forky: "6.16.3-1")

  # The first import is a full one, as the scheduled refresh is, so Debian:14's data is complete here (Backports.data?).
  def import_full(*records) = import_advisories(*records, full: true, origin: "feed")

  def match(*hosts, at: now) = VulnerabilityMatcher.match!(hosts.map(&:id), now: at)

  def report(host, packages) = report_packages(host, packages)

  def finding(host, package, advisory_id) = VulnerabilityFinding.with_details.joins(:advisory).find_by!(host:, package:, advisories: { advisory_id: })

  def rule(host, package, advisory_id) = VulnerabilityTriage.rule_for(finding(host, package, advisory_id).bucket_rule)

  # { package => [advisory ids] } of the host's open findings.
  def open_findings(host)
    VulnerabilityFinding.with_details.joins(:advisory).where(host:, state: %w[open reopened]).order(:package, "advisories.advisory_id")
                        .pluck(:package, "advisories.advisory_id").group_by(&:first).transform_values { |rows| rows.map(&:last) }
  end

  it "finds on a backports kernel what only the release it is built from shows, without counting forky's fix as one, and leaves trixie's kernel to trixie" do
    bpo = debian_host(packages: [ bpo_image, bpo_meta ])
    trixie = debian_host(packages: [ trixie_image, trixie_meta ])
    import_advisories(cve_64253, cve_39748) # not a full import: Debian:14 is not complete yet, so trixie's data alone
    match(bpo, trixie)
    expect(open_findings(bpo)).to eq({})

    result = import_full(cve_64253, cve_39748)
    expect(result.changed_packages["Debian:14"]).to include("linux", "linux-signed-amd64") # every stored backport, the first time
    VulnerabilityMatcher.match_again!
    expect(open_findings(bpo)).to eq(bpo_image[0] => [ "DEBIAN-CVE-2026-64253" ], "linux-image-amd64" => [ "DEBIAN-CVE-2026-64253" ])
    # forky fixes it in 7.1.3-1, but whether trixie-backports has a build at or above it is not known here: no fix.
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-64253"))
      .to have_attributes(state: "open", source: "linux", installed_version: "7.0.9-1~bpo13+1", fixed_version: nil, from_fixed_version: "7.1.3-1", fixable: false)
    expect(rule(bpo, bpo_image[0], "DEBIAN-CVE-2026-64253")).not_to be_in(VulnerabilityTriage::FIX_RULES + %w[K1 K2])
    expect(open_findings(trixie)).to eq(trixie_image[0] => [ "DEBIAN-CVE-2026-64253" ], "linux-image-amd64" => [ "DEBIAN-CVE-2026-64253" ])
    expect(finding(trixie, trixie_image[0], "DEBIAN-CVE-2026-64253")).to have_attributes(fixed_version: "6.12.95-1", from_fixed_version: nil)
  end

  it "only adds: an advisory trixie's data leaves open still matches a backport that forky's data shows fixed" do
    bpo = debian_host(packages: [ bpo_image ])
    import_full(record("DEBIAN-CVE-2026-91002", trixie: nil, forky: "6.16.3-1"), # no fix for trixie yet
                record("DEBIAN-CVE-2026-91003", trixie: :absent, forky: nil))   # in code only newer series have
    match(bpo)
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-91002")).to have_attributes(state: "open", fixed_version: nil, from_fixed_version: nil)
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-91003")).to have_attributes(state: "open", fixed_version: nil, from_fixed_version: nil)
  end

  it "records forky's fix when both releases' data affect a backport, and trixie's as the fix only when trixie's data has one (review S6)" do
    bpo = debian_host(packages: [ bpo_image, [ "libfoo1", "1.2-1~bpo13+1", "foo" ] ])
    import_full(record("DEBIAN-CVE-2026-91010", trixie: nil, forky: "7.1.3-1"),
                record("DEBIAN-CVE-2026-91011", trixie: "1.3-1+deb13u1", forky: "1.4-1", package: "foo"))
    match(bpo)
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-91010")).to have_attributes(fixed_version: nil, from_fixed_version: "7.1.3-1")
    expect(rule(bpo, bpo_image[0], "DEBIAN-CVE-2026-91010")).to eq("L5")
    # The decision form's evidence (VT-OVERRIDES #261) says so too, as the tab's "Fixed in" does.
    candidate = FindingDecisions::Candidates.load(Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-91010"), [ bpo.id ]).sole
    expect(ApplicationController.helpers.decision_fix_words(candidate))
      .to eq("None for this release (fixed in 7.1.3-1 in the release this backport is built from; no backport of it known yet)")
    # trixie's own 1.3-1+deb13u1 sorts above the backport: upgrading installs it, so it is a fix for this release.
    expect(finding(bpo, "libfoo1", "DEBIAN-CVE-2026-91011")).to have_attributes(fixed_version: "1.3-1+deb13u1", from_fixed_version: "1.4-1")
    expect(rule(bpo, "libfoo1", "DEBIAN-CVE-2026-91011")).to eq("F1")
  end

  it "compares a backport at its own version, as OSV does: a backport of the fixed version sorts below it" do
    bpo = debian_host(packages: [ [ "linux-image-7.1.3+deb13-amd64", "7.1.3-1~bpo13+1", "linux-signed-amd64" ] ])
    later = debian_host(packages: [ [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
    import_full(cve_64253)
    match(bpo, later)
    expect(finding(bpo, "linux-image-7.1.3+deb13-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "open", from_fixed_version: "7.1.3-1")
    expect(open_findings(later)).to eq({})
  end

  it "resolves a backport's finding on forky's evidence: fixed when its advisory names the source, not affected when forky's data names the source elsewhere" do
    host = debian_host(packages: [ trixie_image, trixie_meta ])
    import_full(cve_64253, record("DEBIAN-CVE-2026-91004", trixie: "6.12.95-1", forky: :absent),
                record("DEBIAN-CVE-2026-91005", trixie: "6.12.95-1", forky: "6.12.90-1"))
    match(host)
    expect(open_findings(host)["linux-image-amd64"]).to eq(%w[DEBIAN-CVE-2026-64253 DEBIAN-CVE-2026-91004 DEBIAN-CVE-2026-91005])

    # apt install -t trixie-backports linux-image-amd64: the metapackage moves to the backport.
    report(host, [ trixie_image, bpo_meta, bpo_image ])
    match(host, at: now + 1.hour)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "open", fixed_version: nil, from_fixed_version: "7.1.3-1")
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91005")).to have_attributes(state: "resolved", resolution: "fixed")
    # forky's data names linux, but not in 91004: forky is not affected (OSV leaves such a release out).
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91004")).to have_attributes(state: "resolved", resolution: "not_affected")

    later = [ "linux-image-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ]
    report(host, [ trixie_image, later, [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
    match(host, at: now + 2.hours)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "resolved", resolution: "fixed")
  end

  it "resolves a backport's finding on trixie's fix before forky's data is complete, as before #274, and reopens it once forky has no data for its source (review S1, N1)" do
    host = debian_host(packages: [ calibre ])
    import_advisories(record("DEBIAN-CVE-2026-26064", trixie: nil, forky: :absent, package: "calibre")) # not a full import
    match(host)
    import_advisories(record("DEBIAN-CVE-2026-26064", trixie: "8.5.0+ds-1+deb13u2", forky: :absent, package: "calibre", modified: "2026-11-01T00:00:00Z"))
    match(host, at: now + 1.hour)
    expect(finding(host, "calibre", "DEBIAN-CVE-2026-26064")).to have_attributes(state: "resolved", resolution: "fixed")

    import_full(record("DEBIAN-CVE-2026-26064", trixie: "8.5.0+ds-1+deb13u2", forky: :absent, package: "calibre", modified: "2026-11-01T00:00:00Z"), cve_39748)
    VulnerabilityMatcher.match_again!
    expect(finding(host, "calibre", "DEBIAN-CVE-2026-26064")).to have_attributes(state: "reopened", kept: true, fixed_version: nil)
  end

  it "resolves a backport's finding as not affected when neither release's advisory names its source" do
    host = debian_host(packages: [ bpo_image ])
    import_full(record("DEBIAN-CVE-2026-91002", trixie: nil, forky: "6.16.3-1"))
    match(host)
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91002", package: "linux-6.1", fixed: nil, modified: "2026-11-01T00:00:00Z"))
    match(host, at: now + 1.hour)
    expect(finding(host, bpo_image[0], "DEBIAN-CVE-2026-91002")).to have_attributes(state: "resolved", resolution: "not_affected")
  end

  describe "a finding only trixie's data says is fixed, for a source forky has no data for (review B1)" do
    let!(:host) { debian_host(packages: [ calibre ]) }

    def open_in_trixie(**) = record("DEBIAN-CVE-2026-26064", trixie: nil, forky: :absent, package: "calibre", **)
    def fixed_in_trixie = open_in_trixie(trixie: "8.5.0+ds-1+deb13u2", modified: "2026-11-01T00:00:00Z")
    def calibre_finding = finding(host, "calibre", "DEBIAN-CVE-2026-26064")

    before do
      import_full(open_in_trixie, cve_39748)
      match(host)
      expect(calibre_finding).to have_attributes(state: "open", kept: false)
      import_advisories(fixed_in_trixie) # trixie fixes it below the backport's version: no evidence for the backport
      match(host, at: now + 1.hour)
    end

    it "is kept open with a verdict, never opened anew, and resolves on removal, withdrawal, or forky's data naming the source" do
      expect(calibre_finding).to have_attributes(state: "open", kept: true, fixed_version: nil, installed_version: calibre[1])
      expect(ChunkMatch.where(keep_only: true).count).to eq(1)
      other = debian_host(packages: [ calibre ]) # the same chunk: its keep_only verdict opens nothing
      match(other)
      expect(open_findings(other)).to eq({})

      # An upgrade of the backport: still kept, at the version now installed.
      report(host, [ [ "calibre", "9.4.0+ds-1~bpo13+1", "calibre" ] ])
      match(host, at: now + 2.hours)
      expect(calibre_finding).to have_attributes(state: "open", kept: true, installed_version: "9.4.0+ds-1~bpo13+1")

      # forky's data names calibre (another CVE): this advisory not naming it there means forky is not affected.
      import_advisories(record("DEBIAN-CVE-2026-91012", trixie: :absent, forky: "9.3.0+ds+~0.10.5-1", package: "calibre"))
      match(host, at: now + 3.hours)
      expect(calibre_finding).to have_attributes(state: "resolved", resolution: "not_affected")
    end

    # A recorded decision (VT-OVERRIDES #261) on a kept finding: keep_only keeps the finding open and triaged, so the
    # control keeps applying (O1) and the decision stays; it ends only when the finding resolves on forky's evidence,
    # as for any finding. Trixie's fix is no evidence here, so it is not a fix that ends the decision either.
    it "keeps a recorded control applying while the finding is kept, and ends it when forky's data resolves the finding" do
      travel_to(now + 1.hour)
      advisory = Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-26064")
      candidate = FindingDecisions::Candidates.load(advisory, [ host.id ]).sole
      expect(ApplicationController.helpers.decision_fix_words(candidate))
        .to eq("None for this release (kept open: only this release's data says it is fixed, which is no evidence for a backport)")
      outcome = FindingDecisions.record!(operator: create(:operator), host:, advisory:,
                                         params: { kind: "control", reason: "calibre-server is not started on this host", expires_on: (Date.current + 30).iso8601,
                                                   host_ids: [ host.id ], confirmed_ids: [ host.id ] })
      expect(outcome).to be_saved
      expect(rule(host, "calibre", "DEBIAN-CVE-2026-26064")).to eq("O1")

      match(host, at: now + 2.hours) # trixie's fix again: still kept, still controlled
      expect(calibre_finding).to have_attributes(state: "open", kept: true)
      expect(rule(host, "calibre", "DEBIAN-CVE-2026-26064")).to eq("O1")
      expect(FindingDecision.sole).to be_active

      import_advisories(record("DEBIAN-CVE-2026-91012", trixie: :absent, forky: "9.3.0+ds+~0.10.5-1", package: "calibre"))
      VulnerabilityMatcher.match_again! # the same chunk, matched again on the new data
      expect(calibre_finding).to have_attributes(state: "resolved", resolution: "not_affected")
      expect(FindingDecision.sole).to have_attributes(ended_why: "resolved")
    end

    it "resolves on withdrawal and removal" do
      second = debian_host(packages: [ calibre ])
      match(second)
      import_advisories(fixed_in_trixie.merge("modified" => "2026-11-02T00:00:00Z", "withdrawn" => "2026-11-02T00:00:00Z"))
      match(host, at: now + 2.hours)
      expect(calibre_finding).to have_attributes(state: "resolved", resolution: "withdrawn")
      report(second, [ [ "openssl", "3.5.0-1", "openssl" ] ])
      match(second, at: now + 2.hours)
      expect(VulnerabilityFinding.where(host: second).pluck(:state)).to all(eq("resolved"))
    end

    it "is never resolved on trixie's fix, even with its verdict gone" do
      ChunkMatch.where(keep_only: true).delete_all # as if the verdict were missing
      match(host, at: now + 2.hours)
      expect(calibre_finding).to have_attributes(state: "open")
    end

    it "is re-triaged: a listener, KEV, EPSS, and a control reach it" do
      saved = VulnerabilityTriage::HostFacts.listener_source
      controls = VulnerabilityTriage::HostFacts.control_source # FindingDecisions::ControlSource since #261, restored below
      VulnerabilityTriage::HostFacts.listener_source = nil
      match(host, at: now + 1.hour)
      expect(rule(host, "calibre", "DEBIAN-CVE-2026-26064")).to eq("L5")
      listener = VulnerabilityTriage::Listener.new(package: "calibre", network: true, unit: "calibre-server.service", addresses: [], scanned_at: 1.hour.ago)
      VulnerabilityTriage::HostFacts.listener_source = Class.new do
        define_method(:listeners) { |ids, package_sets:, now:| ids.index_with { { "calibre" => listener } } }
      end.new
      match(host, at: now + 2.hours)
      expect(rule(host, "calibre", "DEBIAN-CVE-2026-26064")).to eq("N5")
      VulnerabilityTriage::HostFacts.listener_source = nil
      match(host, at: now + 2.hours)

      import_kev(kev_file("CVE-2026-91999")) # KEV data appears: every host is re-triaged (a full run)
      perform_evaluation_jobs
      import_kev(kev_file("CVE-2026-91999", "CVE-2026-26064")) # this CVE: a run for its advisory only (retriage!)
      perform_evaluation_jobs
      expect(EvaluationRun.where(kind: "triage").last.scope).to include("full" => false, "advisories" => 1)
      expect(calibre_finding).to have_attributes(bucket_rule: VulnerabilityTriage::RULE_IDS["N1"], kev: true)

      import_kev(kev_file("CVE-2026-91999"), allowed_drops: 1)
      import_epss(epss_file([ [ "CVE-2026-26064", "0.42", "0.97" ] ]))
      perform_evaluation_jobs { EvaluationRun.start!("triage", { "reason" => "daily" }) }
      expect(rule(host, "calibre", "DEBIAN-CVE-2026-26064")).to eq("N2")

      advisory = Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-26064").id
      VulnerabilityTriage::HostFacts.control_source = Class.new { define_method(:controls) { |ids, **| ids.index_with { Set[advisory] } } }.new
      match(host, at: now + 2.hours)
      expect(rule(host, "calibre", "DEBIAN-CVE-2026-26064")).to eq("O1")
    ensure
      VulnerabilityTriage::HostFacts.listener_source = saved
      VulnerabilityTriage::HostFacts.control_source = controls
    end
  end

  it "keeps a backport left from bookworm-backports (~bpo12, built from trixie's version) to trixie's data" do
    host = debian_host(packages: [ [ "linux-image-6.12.38+deb12-amd64", "6.12.38-1~bpo12+1", "linux-signed-amd64" ] ])
    import_full(cve_64253)
    match(host)
    expect(finding(host, "linux-image-6.12.38+deb12-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "open", fixed_version: "6.12.95-1")
  end

  it "says which ecosystem a backport's range could not be compared in" do
    host = debian_host(packages: [ bpo_image ])
    bad = record("DEBIAN-CVE-2026-91006", trixie: "6.12.95-1", forky: "7.1.3-1")
    bad["affected"].last["ranges"].first["events"] << { "fixed" => "bad:version" }
    import_full(bad)
    match(host)
    reasons = HostVulnerabilityEvaluation.find_by!(host_id: host.id).not_evaluated.map { |e| e["reason"] }
    expect(reasons).to eq([ "Debian:14: advisory version bad:version is not valid: #{PackageVersions.for('dpkg').parse('bad:version').reason}" ])
  end

  describe "the triage of a backport" do
    let(:trixie_host) { debian_host(packages: [ trixie_image ]) }
    let(:bpo_host) { debian_host(packages: [ bpo_image ]) }

    it "does not use Debian's triage for the release to clear or demote it, but keeps what escalates" do
      import_full(*%w[91007 91008 91009 91013].map { |n| record("DEBIAN-CVE-2026-#{n}", trixie: nil, forky: nil) })
      document = tracker_document("linux" => {
        "CVE-2026-91007" => { "trixie" => tracker_release(status: "resolved", fixed_version: "6.12.43-1") }, # at or below both kernels
        "CVE-2026-91008" => { "trixie" => tracker_release(status: "resolved", fixed_version: "0") },         # trixie's code is not affected
        "CVE-2026-91009" => { "trixie" => tracker_release(status: "open", urgency: "end-of-life") },
        "CVE-2026-91013" => { "trixie" => tracker_release(status: "open") }
      })
      document["linux"]["CVE-2026-91013"]["scope"] = "local" # with no CVSS vector, trixie's local scope gives trixie L2 (review N2)
      import_triage(document)
      match(trixie_host, bpo_host)
      pairs = %w[91007 91008 91009 91013].map { |n| [ rule(trixie_host, trixie_image[0], "DEBIAN-CVE-2026-#{n}"), rule(bpo_host, bpo_image[0], "DEBIAN-CVE-2026-#{n}") ] }
      expect(pairs).to eq([ %w[I4 N4], %w[I3 N4], %w[N3 N3], %w[L2 L5] ])
    end

    it "counts an installed image toward a reboot's fix only for a fix of its own series, by the host release's marker" do
      import_full(cve_64253)
      trixie = debian_host(packages: [ trixie_image, bpo_image ]).tap { |h| record_inventory(h, kernel_version: "6.12.48+deb13-amd64") }
      bpo = debian_host(packages: [ bpo_image, [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
            .tap { |h| record_inventory(h, kernel_version: "7.0.9+deb13-amd64") }
      alone = debian_host(packages: [ bpo_image ]).tap { |h| record_inventory(h, kernel_version: "7.0.9+deb13-amd64") }
      old_bpo = [ "linux-image-6.12.96+deb12-amd64", "6.12.96-1~bpo12+1", "linux-signed-amd64" ] # bookworm-backports: trixie's own series
      left = debian_host(packages: [ trixie_image, old_bpo ]).tap { |h| record_inventory(h, kernel_version: "6.12.48+deb13-amd64") }
      match(trixie, bpo, alone, left)
      # 7.0.9-1~bpo13+1 sorts above trixie's fix, 6.12.95-1, but forky's data says it is affected: not "reboot into it".
      expect(rule(trixie, trixie_image[0], "DEBIAN-CVE-2026-64253")).to eq("K2")
      expect(rule(trixie, bpo_image[0], "DEBIAN-CVE-2026-64253")).to eq("I1")
      # An installed backport at or above forky's 7.1.3-1 proves one exists: reboot into it.
      expect(rule(bpo, bpo_image[0], "DEBIAN-CVE-2026-64253")).to eq("K1")
      expect(VulnerabilityTriage::Explain.load(VulnerabilityFinding.with_details.active.where(host: bpo, package: bpo_image[0])).values.sole)
        .to have_attributes(from_fixed_version: "7.1.3-1", backport: true)
      # None installed: not a fix, so neither K1 nor K2.
      expect(rule(alone, bpo_image[0], "DEBIAN-CVE-2026-64253")).to eq("L5")
      expect(rule(left, trixie_image[0], "DEBIAN-CVE-2026-64253")).to eq("K1") # review N1
    end

    it "says in the reasons that forky's fix is not counted, and why a kept finding is open" do
      import_full(cve_64253)
      match(bpo_host)
      f = VulnerabilityFinding.with_details.active.where(host: bpo_host).to_a
      inputs = VulnerabilityTriage::Explain.load(f).fetch(f.sole.id)
      expect(VulnerabilityTriage::Reasons.sentence("L5", inputs))
        .to end_with("Fixed in 7.1.3-1 in the release this backport is built from, with no backport above it known here yet, so it is not counted as a fix.")
      expect(VulnerabilityTriage::Reasons.sentence("K1", inputs)).to eq("Fixed in 7.1.3-1, which is installed. Reboot into it.")
      expect(VulnerabilityTriage::Reasons.sentence("L5", inputs.with(kept: true, from_fixed_version: nil)))
        .to end_with("Kept open: only this release's data says it is fixed, which is no evidence for a backport, and the release it is built from has no data for linux.")
    end
  end

  describe "re-matching after a change to the release backports are built from (ADR 0028)" do
    let!(:bpo) { debian_host(packages: [ bpo_image, [ "openssl", "3.5.0-1", "openssl" ] ]) }
    let!(:trixie) { debian_host(packages: [ trixie_image, [ "openssl", "3.5.0-1", "openssl" ] ]) }

    def evaluated_at(host) = ChunkEvaluation.where(package_chunk_id: PackageStore.chunk_ids_of(HostPackageSet.find_by!(host_id: host.id).package_set_id)).pluck(:evaluated_at)

    it "touches only the chunks and hosts holding a backport of the changed sources" do
      import_full(cve_64253)
      match(bpo, trixie)
      expect(EvaluationRun::Advisories.new("packages" => { "Debian:14" => [ "linux" ] }).hosts.pluck(:id)).to eq([ bpo.id ])
      expect(EvaluationRun::Advisories.new("packages" => { "Debian:13" => [ "linux" ] }).hosts.pluck(:id)).to contain_exactly(bpo.id, trixie.id)
      expect(EvaluationRun::Advisories.new("packages" => { "Debian:14" => [ "openssl" ] }).hosts.pluck(:id)).to eq([])
      expect(EvaluationRun::Advisories.new("packages" => { "Debian:14" => [] }).hosts.pluck(:id)).to eq([])
      expect(EvaluationRun::Advisories.new("packages" => { "Debian:12" => [ "linux" ] }).hosts.pluck(:id)).to eq([])

      # An advisory in code only newer series have names forky alone: it re-matches the backport's chunk, and the
      # trixie host's chunks are moved to the new import as they are.
      before = { bpo: evaluated_at(bpo), trixie: evaluated_at(trixie) }
      travel(1.hour) do
        result = import_advisories(record("DEBIAN-CVE-2026-91003", trixie: :absent, forky: nil))
        expect(result.changed_packages).to eq("Debian:14" => [ "linux" ])
        EvaluationRun::Advisories.new("packages" => result.changed_packages).prepare!
      end
      expect(evaluated_at(bpo)).not_to eq(before[:bpo])
      expect(evaluated_at(trixie)).to eq(before[:trixie])
      expect(ChunkEvaluation.distinct.pluck(:advisory_import_id)).to eq([ AdvisoryImport.newest_succeeded_id ])
      match(bpo, trixie, at: now + 1.hour)
      expect(open_findings(bpo)[bpo_image[0]]).to eq(%w[DEBIAN-CVE-2026-64253 DEBIAN-CVE-2026-91003])
      expect(open_findings(trixie)[trixie_image[0]]).to eq([ "DEBIAN-CVE-2026-64253" ])
    end

    it "does not move a backport's chunk to an import that changed its source in the release it is built from" do
      import_full(cve_64253)
      match(bpo, trixie)
      import = travel(1.hour) { import_advisories(record("DEBIAN-CVE-2026-91003", trixie: :absent, forky: nil)).import }
      VulnerabilityMatcher::Chunks.restamp!(import.id)
      bpo_chunks = PackageStore.chunk_ids_of(HostPackageSet.find_by!(host_id: bpo.id).package_set_id)
      stale = ChunkEvaluation.where.not(advisory_import_id: import.id).pluck(:package_chunk_id)
      expect(stale).not_to be_empty
      expect(stale - bpo_chunks).to eq([])
    end

    it "carries a backports re-match through a failure and EvaluationRun.retry! (#292)" do
      import_full(cve_64253)
      allow(Ecosystems).to receive(:backports_from).and_return(nil) # matched as before #274
      match(bpo, trixie)
      allow(Ecosystems).to receive(:backports_from).and_call_original
      expect(open_findings(bpo)).to eq({})

      run = EvaluationRun.start!("advisories", EvaluationRun::Advisories.backports_scope)
      allow(VulnerabilityMatcher).to receive(:match!).and_raise(ActiveRecord::Deadlocked)
      perform_evaluation_jobs rescue nil # rubocop:disable Style/RescueModifier
      EvaluationRun.fail!(run.id)
      expect(run.reload).to be_failed

      allow(VulnerabilityMatcher).to receive(:match!).and_call_original
      carried = perform_evaluation_jobs { EvaluationRun.retry!(run) }
      expect(carried.reload).to have_attributes(state: "finished", host_count: 1)
      expect(open_findings(bpo)).to eq(bpo_image[0] => [ "DEBIAN-CVE-2026-64253" ])
      expect(open_findings(trixie)).to eq(trixie_image[0] => [ "DEBIAN-CVE-2026-64253" ])
    end

    it "re-matches only the backports with bin/rails vulnerabilities:rematch_backports's scope, and every backport's source" do
      import_full(cve_64253)
      match(bpo, trixie)
      expect(EvaluationRun::Advisories.backports_scope).to eq("packages" => { "Debian:14" => %w[linux linux-signed-amd64] }, "reason" => "matching")
      expect(EvaluationRun::Advisories.new(EvaluationRun::Advisories.backports_scope).hosts.pluck(:id)).to eq([ bpo.id ])
      stub_const("Ecosystems::BACKPORTS", {})
      expect(EvaluationRun::Advisories.backports_scope).to be_nil
      expect(Backports.sources("Debian:13")).to eq([])
      expect(Backports).not_to be_data("Debian:13")
    end
  end

  describe "Debian:14's data" do
    it "is complete once a full import kept it, malformed records and Debian:14 entries counted, not holding it back (review S2)" do
      import_advisories(cve_64253)
      expect(Backports).not_to be_data("Debian:13")
      expect(Backports.status("Debian:13")).to have_attributes(from: "Debian:14", complete: false, import: nil, skipped_entries: 0, malformed: 0)
      bad_forky = cve_39748.tap { |r| r["affected"].last["ranges"].first["events"] = [ { "fixed" => "6.16.3-1" } ] } # no introduced event
      result = import_advisories(cve_64253, bad_forky, "not json", full: true)
      expect(Backports).to be_data("Debian:13")
      expect(Backports.status("Debian:13")).to have_attributes(complete: true, import: result.import, skipped_entries: 1, malformed: 1)
      # The bad forky entry costs its record nothing for trixie.
      expect(AdvisoryPackage.joins(:advisory).where(advisories: { advisory_id: "DEBIAN-CVE-2025-39748" }).pluck(:ecosystem)).to eq([ "Debian:13" ])
      expect(Backports.status("Debian:14")).to be_nil
      expect(Backports).not_to be_data("Debian:14")
    end

    it "is written again for an advisory stored before Debian:14 was kept, and only it counts as changed" do
      allow(Ecosystems).to receive(:imported?).and_wrap_original { |original, ecosystem| ecosystem == "Debian:13" && original.call(ecosystem) }
      import_advisories(cve_64253)
      expect(AdvisoryPackage.pluck(:ecosystem)).to eq([ "Debian:13" ])

      allow(Ecosystems).to receive(:imported?).and_call_original
      result = import_advisories(cve_64253)
      expect(result.import.counts).to include("updated" => 1, "unchanged" => 0)
      expect(result.changed_packages).to eq("Debian:14" => [ "linux" ])
      expect(AdvisoryPackage.order(:ecosystem).pluck(:ecosystem)).to eq(%w[Debian:13 Debian:14])

      again = import_advisories(cve_64253)
      expect(again.import.counts).to include("updated" => 0, "unchanged" => 1)
      expect(again.changed_packages).to eq({})
    end
  end
end
