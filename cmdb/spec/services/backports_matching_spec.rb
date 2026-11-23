require "rails_helper"

# Backports are matched against the release they are built from (#274, Ecosystems::BACKPORTS). Package names and
# versions are Debian's: trixie's kernel linux 6.12.48-1 (linux-image-6.12.48+deb13-amd64 from linux-signed-amd64), and
# trixie-backports' linux 7.0.9-1~bpo13+1 (linux-image-7.0.9+deb13-amd64 from linux-signed-amd64 7.0.9+1~bpo13+1). The
# advisories follow Debian's data: DEBIAN-CVE-2025-39748 is fixed in trixie by 6.12.43-1 and in forky (Debian:14) by
# 6.16.3-1, as OSV publishes it; CVE-2026-64253 is fixed in trixie by 6.12.95-1 and in forky and sid by 7.1.3-1, as the
# security tracker lists it. DEBIAN-CVE-2026-91xxx are made up.
RSpec.describe "Matching backports (#274)" do # rubocop:disable RSpec/DescribeClass
  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  let(:now) { Time.utc(2026, 11, 22, 12) }
  let(:trixie_image) { [ "linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:trixie_meta) { [ "linux-image-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:bpo_image) { [ "linux-image-7.0.9+deb13-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ] }
  let(:bpo_meta) { [ "linux-image-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ] }

  # One advisory naming linux in Debian:13 (trixie's fix) and Debian:14 (forky's); :absent leaves an ecosystem out.
  def kernel_record(id, trixie:, forky:, **extra)
    affected = { "Debian:13" => trixie, "Debian:14" => forky }.reject { |_, fixed| fixed == :absent }.map do |ecosystem, fixed|
      osv_record(id:, package: "linux", fixed:, ecosystem:)["affected"].first
    end
    osv_record(id:, **extra).merge("affected" => affected)
  end

  def cve_64253(**) = kernel_record("DEBIAN-CVE-2026-64253", trixie: "6.12.95-1", forky: "7.1.3-1", **)
  def cve_39748 = kernel_record("DEBIAN-CVE-2025-39748", trixie: "6.12.43-1", forky: "6.16.3-1")

  def match(*hosts, at: now) = VulnerabilityMatcher.match!(hosts.map(&:id), now: at)

  def report(host, packages) = report_packages(host, packages)

  def finding(host, package, advisory_id) = VulnerabilityFinding.with_details.joins(:advisory).find_by!(host:, package:, advisories: { advisory_id: })

  # { package => [advisory ids] } of the host's open findings.
  def open_findings(host)
    VulnerabilityFinding.with_details.joins(:advisory).where(host:, state: %w[open reopened]).order(:package, "advisories.advisory_id")
                        .pluck(:package, "advisories.advisory_id").group_by(&:first).transform_values { |rows| rows.map(&:last) }
  end

  it "finds on a backports kernel what only the release it is built from shows, and leaves a trixie kernel to trixie's data" do
    bpo = debian_host(packages: [ bpo_image, bpo_meta ])
    trixie = debian_host(packages: [ trixie_image, trixie_meta ])
    import_advisories(cve_64253, cve_39748)

    allow(Ecosystems).to receive(:backports_from).and_return(nil) # before #274: trixie's ranges only, and 7.0.9 > 6.12.95-1
    match(bpo, trixie)
    expect(open_findings(bpo)).to eq({})

    allow(Ecosystems).to receive(:backports_from).and_call_original
    VulnerabilityMatcher.match_again!
    expect(open_findings(bpo)).to eq(bpo_image[0] => [ "DEBIAN-CVE-2026-64253" ], "linux-image-amd64" => [ "DEBIAN-CVE-2026-64253" ])
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-64253"))
      .to have_attributes(state: "open", source: "linux", installed_version: "7.0.9-1~bpo13+1", fixed_version: "7.1.3-1")
    # The trixie host is matched against trixie's data alone: its fix is trixie's, and forky's 7.1.3-1 plays no part.
    expect(open_findings(trixie)).to eq(trixie_image[0] => [ "DEBIAN-CVE-2026-64253" ], "linux-image-amd64" => [ "DEBIAN-CVE-2026-64253" ])
    expect(finding(trixie, trixie_image[0], "DEBIAN-CVE-2026-64253")).to have_attributes(fixed_version: "6.12.95-1")
  end

  it "only adds: an advisory trixie's data leaves open still matches a backport that forky's data shows fixed" do
    bpo = debian_host(packages: [ bpo_image ])
    import_advisories(kernel_record("DEBIAN-CVE-2026-91002", trixie: nil, forky: "6.16.3-1"), # no fix for trixie yet
                      kernel_record("DEBIAN-CVE-2026-91003", trixie: :absent, forky: nil))   # in code only newer series have
    match(bpo)
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-91002")).to have_attributes(state: "open", fixed_version: nil)
    expect(finding(bpo, bpo_image[0], "DEBIAN-CVE-2026-91003")).to have_attributes(state: "open", fixed_version: nil, last_ecosystem: "Debian:13")
  end

  it "compares a backport at its own version, as OSV does: a backport of the fixed version sorts below it" do
    bpo = debian_host(packages: [ [ "linux-image-7.1.3+deb13-amd64", "7.1.3-1~bpo13+1", "linux-signed-amd64" ] ])
    later = debian_host(packages: [ [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
    import_advisories(cve_64253)
    match(bpo, later)
    expect(finding(bpo, "linux-image-7.1.3+deb13-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "open", fixed_version: "7.1.3-1")
    expect(open_findings(later)).to eq({})
  end

  it "resolves a backport's finding as fixed only on the evidence of the release it is built from, and keeps it otherwise" do
    host = debian_host(packages: [ trixie_image, trixie_meta ])
    import_advisories(cve_64253, kernel_record("DEBIAN-CVE-2026-91004", trixie: "6.12.95-1", forky: :absent),
                      kernel_record("DEBIAN-CVE-2026-91005", trixie: "6.12.95-1", forky: :absent))
    match(host)
    expect(open_findings(host)["linux-image-amd64"]).to eq(%w[DEBIAN-CVE-2026-64253 DEBIAN-CVE-2026-91004 DEBIAN-CVE-2026-91005])

    # apt install -t trixie-backports linux-image-amd64: the metapackage moves to the backport.
    report(host, [ trixie_image, bpo_meta, bpo_image ])
    match(host, at: now + 1.hour)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "open", fixed_version: "7.1.3-1", installed_version: "7.0.9-1~bpo13+1")
    # trixie's 6.12.95-1 is below 7.0.9, but forky's data names nothing for 91004: that is no evidence, so it stays open.
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91004")).to have_attributes(state: "open", resolved_at: nil)
    expect(open_findings(host)[bpo_image[0]]).to eq([ "DEBIAN-CVE-2026-64253" ]) # the new image: forky's data only

    later = [ "linux-image-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ]
    report(host, [ trixie_image, later, [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
    match(host, at: now + 2.hours)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "resolved", resolution: "fixed")
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91004")).to have_attributes(state: "open")

    # Unambiguous evidence still resolves it: forky's data showing it fixed, a withdrawal, or the package's removal.
    import_advisories(kernel_record("DEBIAN-CVE-2026-91004", trixie: "6.12.95-1", forky: "7.2.1-1", modified: "2026-11-01T00:00:00Z"),
                      kernel_record("DEBIAN-CVE-2026-91005", trixie: "6.12.95-1", forky: :absent, modified: "2026-11-01T00:00:00Z",
                                                             withdrawn: "2026-11-01T00:00:00Z"))
    match(host, at: now + 3.hours)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91004")).to have_attributes(state: "resolved", resolution: "fixed")
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91005")).to have_attributes(state: "resolved", resolution: "withdrawn")
  end

  it "resolves a backport's finding as not affected only when neither release's advisory names its source" do
    host = debian_host(packages: [ bpo_image ])
    import_advisories(kernel_record("DEBIAN-CVE-2026-91002", trixie: nil, forky: "6.16.3-1"))
    match(host)
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91002", package: "linux-6.1", fixed: nil, modified: "2026-11-01T00:00:00Z"))
    match(host, at: now + 1.hour)
    expect(finding(host, bpo_image[0], "DEBIAN-CVE-2026-91002")).to have_attributes(state: "resolved", resolution: "not_affected")
  end

  it "keeps a backport left from bookworm-backports (~bpo12, built from trixie's version) to trixie's data" do
    host = debian_host(packages: [ [ "linux-image-6.12.38+deb12-amd64", "6.12.38-1~bpo12+1", "linux-signed-amd64" ] ])
    import_advisories(cve_64253)
    match(host)
    expect(finding(host, "linux-image-6.12.38+deb12-amd64", "DEBIAN-CVE-2026-64253")).to have_attributes(state: "open", fixed_version: "6.12.95-1")
  end

  it "says which ecosystem a backport's range could not be compared in" do
    host = debian_host(packages: [ bpo_image ])
    record = kernel_record("DEBIAN-CVE-2026-91006", trixie: "6.12.95-1", forky: "7.1.3-1")
    record["affected"].last["ranges"].first["events"] << { "fixed" => "bad:version" }
    import_advisories(record)
    match(host)
    reasons = HostVulnerabilityEvaluation.find_by!(host_id: host.id).not_evaluated.map { |e| e["reason"] }
    expect(reasons).to eq([ "Debian:14: advisory version bad:version is not valid: #{PackageVersions.for('dpkg').parse('bad:version').reason}" ])
  end

  describe "the triage of a backport" do
    let(:trixie_host) { debian_host(packages: [ trixie_image ]) }
    let(:bpo_host) { debian_host(packages: [ bpo_image ]) }

    def rule(host, package, advisory_id) = VulnerabilityTriage.rule_for(finding(host, package, advisory_id).bucket_rule)

    it "does not use Debian's triage for the release to clear or demote it, but keeps what is about the CVE" do
      import_advisories(kernel_record("DEBIAN-CVE-2026-91007", trixie: nil, forky: :absent), kernel_record("DEBIAN-CVE-2026-91008", trixie: nil, forky: :absent),
                        kernel_record("DEBIAN-CVE-2026-91009", trixie: nil, forky: :absent))
      import_triage(tracker_document("linux" => {
        "CVE-2026-91007" => { "trixie" => tracker_release(status: "resolved", fixed_version: "6.12.43-1") }, # at or below both kernels
        "CVE-2026-91008" => { "trixie" => tracker_release(status: "resolved", fixed_version: "0") }, # trixie's code is not affected
        "CVE-2026-91009" => { "trixie" => tracker_release(status: "open", urgency: "end-of-life") }
      }))
      match(trixie_host, bpo_host)
      expect([ rule(trixie_host, trixie_image[0], "DEBIAN-CVE-2026-91007"), rule(bpo_host, bpo_image[0], "DEBIAN-CVE-2026-91007") ]).to eq(%w[I4 N4])
      expect([ rule(trixie_host, trixie_image[0], "DEBIAN-CVE-2026-91008"), rule(bpo_host, bpo_image[0], "DEBIAN-CVE-2026-91008") ]).to eq(%w[I3 N4])
      expect([ rule(trixie_host, trixie_image[0], "DEBIAN-CVE-2026-91009"), rule(bpo_host, bpo_image[0], "DEBIAN-CVE-2026-91009") ]).to eq(%w[N3 N3])
    end

    it "counts an installed image toward a reboot's fix only for a fix of its own series" do
      import_advisories(cve_64253)
      trixie = debian_host(packages: [ trixie_image, bpo_image ]).tap { |h| record_inventory(h, kernel_version: "6.12.48+deb13-amd64") }
      bpo = debian_host(packages: [ bpo_image, [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
            .tap { |h| record_inventory(h, kernel_version: "7.0.9+deb13-amd64") }
      match(trixie, bpo)
      # 7.0.9-1~bpo13+1 sorts above trixie's fix, 6.12.95-1, but forky's data says it is affected: not "reboot into it".
      expect(rule(trixie, trixie_image[0], "DEBIAN-CVE-2026-64253")).to eq("K2")
      expect(rule(trixie, bpo_image[0], "DEBIAN-CVE-2026-64253")).to eq("I1")
      expect(rule(bpo, bpo_image[0], "DEBIAN-CVE-2026-64253")).to eq("K1") # 7.3.4-1~bpo13+1 is above forky's 7.1.3-1
    end

    it "says in a fix's reason that a backport of the fixed version sorts below it" do
      import_advisories(cve_64253)
      match(bpo_host)
      f = VulnerabilityFinding.with_details.active.where(host: bpo_host).to_a
      inputs = VulnerabilityTriage::Explain.load(f)
      text = VulnerabilityTriage::Reasons.sentence("F1", inputs.fetch(f.sole.id))
      expect(text).to eq("Debian fixed it in 7.1.3-1; this host has 7.0.9-1~bpo13+1. This is a backport: it is fixed once the installed backport's " \
                         "version sorts above 7.1.3-1 (a backport of 7.1.3-1 itself sorts below it).")
    end
  end

  describe "re-matching after a change to the release backports are built from (ADR 0028)" do
    let!(:bpo) { debian_host(packages: [ bpo_image, [ "openssl", "3.5.0-1", "openssl" ] ]) }
    let!(:trixie) { debian_host(packages: [ trixie_image, [ "openssl", "3.5.0-1", "openssl" ] ]) }

    def evaluated_at(host) = ChunkEvaluation.where(package_chunk_id: PackageStore.chunk_ids_of(HostPackageSet.find_by!(host_id: host.id).package_set_id)).pluck(:evaluated_at)

    it "touches only the chunks and hosts holding a backport of the changed sources" do
      import_advisories(cve_64253)
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
        result = import_advisories(kernel_record("DEBIAN-CVE-2026-91003", trixie: :absent, forky: nil))
        expect(result.changed_packages).to eq("Debian:14" => [ "linux" ])
        EvaluationRun::Advisories.new("packages" => result.changed_packages).prepare!
      end
      expect(evaluated_at(bpo)).not_to eq(before[:bpo])
      expect(evaluated_at(trixie)).to eq(before[:trixie])
      stamp = AdvisoryImport.newest_succeeded_id
      expect(ChunkEvaluation.distinct.pluck(:advisory_import_id)).to eq([ stamp ])
      match(bpo, trixie, at: now + 1.hour)
      expect(open_findings(bpo)[bpo_image[0]]).to eq(%w[DEBIAN-CVE-2026-64253 DEBIAN-CVE-2026-91003])
      expect(open_findings(trixie)[trixie_image[0]]).to eq([ "DEBIAN-CVE-2026-64253" ])
    end

    it "does not move a backport's chunk to an import that changed its source in the release it is built from" do
      import_advisories(cve_64253)
      match(bpo, trixie)
      import = travel(1.hour) { import_advisories(kernel_record("DEBIAN-CVE-2026-91003", trixie: :absent, forky: nil)).import }
      VulnerabilityMatcher::Chunks.restamp!(import.id)
      bpo_chunks = PackageStore.chunk_ids_of(HostPackageSet.find_by!(host_id: bpo.id).package_set_id)
      stale = ChunkEvaluation.where.not(advisory_import_id: import.id).pluck(:package_chunk_id)
      expect(stale).not_to be_empty
      expect(stale - bpo_chunks).to eq([])
    end
  end

  describe "an advisory stored before Debian:14 was kept" do
    it "is written again with its Debian:14 packages, and only those count as changed" do
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
