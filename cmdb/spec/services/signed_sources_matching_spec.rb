require "rails_helper"

# Signed-template packages get the findings of the source they are built from (#270): the running kernel's signed
# image and its metapackage as linux, shim-signed as shim. Package names, sources, and versions are a Debian 13 amd64
# host's (linux-signed-amd64 6.12.48+1 and 6.12.88+1, built from linux 6.12.48-1 and 6.12.88-1; shim-signed
# 1.51~1+deb13u1 from shim 16.1-2~deb13u1, which depends on shim-helpers-amd64-signed 1+16.1+2~deb13u1, which depends
# on shim-unsigned 16.1-2~deb13u1 (source shim); grub-efi-amd64-signed 1+2.12+9+deb13u2 from grub2 2.12-9+deb13u2;
# fwupd-amd64-signed 1:1.7+1 from fwupd-efi 1:1.7-1). The advisory ids are made up.
RSpec.describe "Matching signed-template packages (#270)" do # rubocop:disable RSpec/DescribeClass
  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  let(:now) { Time.utc(2026, 11, 19, 12) }

  # A Debian 13 amd64 host's packages: [name, version, reported source].
  let(:running) { [ "linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:meta) { [ "linux-image-amd64", "6.12.48-1", "linux-signed-amd64" ] }
  let(:libc) { [ "linux-libc-dev", "6.12.48-1", "linux" ] }
  let(:shim) { [ "shim-signed", "1.51~1+deb13u1+16.1-2~deb13u1", "shim-signed" ] }
  let(:packages) do
    [ running, meta, libc,
      [ "linux-headers-6.12.48+deb13-amd64", "6.12.48-1", "linux" ], [ "linux-headers-6.12.48+deb13-common", "6.12.48-1", "linux" ],
      shim, [ "shim-signed-common", "1.51~1+deb13u1+16.1-2~deb13u1", "shim-signed" ],
      [ "shim-helpers-amd64-signed", "1+16.1+2~deb13u1", "shim-helpers-amd64-signed" ], [ "shim-unsigned", "16.1-2~deb13u1", "shim" ],
      [ "grub-efi-amd64-signed", "1+2.12+9+deb13u2", "grub-efi-amd64-signed" ], [ "grub-common", "2.12-9+deb13u2", "grub2" ],
      [ "grub-efi-amd64-bin", "2.12-9+deb13u2", "grub2" ], [ "fwupd-amd64-signed", "1:1.7+1", "fwupd-amd64-signed" ], [ "openssl", "3.5.0-1", "openssl" ] ]
  end

  def advisories
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91001", package: "linux", fixed: "6.12.88-1"),  # fixed in trixie-security
                      osv_record(id: "DEBIAN-CVE-2026-91002", package: "linux", fixed: nil),          # no fix yet
                      osv_record(id: "DEBIAN-CVE-2026-91003", package: "linux", fixed: "6.12.43-1"),  # fixed before the running kernel
                      osv_record(id: "DEBIAN-CVE-2026-91004", package: "shim", fixed: nil),
                      osv_record(id: "DEBIAN-CVE-2026-91005", package: "shim", fixed: "15.8-1"),      # fixed before trixie's shim
                      osv_record(id: "DEBIAN-CVE-2026-91006", package: "grub2", fixed: "2.12-9+deb13u3"),
                      osv_record(id: "DEBIAN-CVE-2026-91007", package: "fwupd-efi", fixed: nil))
  end

  def report(host, packages) = report_packages(host, packages)

  def match(host, at: now) = VulnerabilityMatcher.match!([ host.id ], now: at)

  # { package => [advisory ids] } of the host's open findings.
  def open_findings(host)
    VulnerabilityFinding.with_details.joins(:advisory).where(host:, state: %w[open reopened]).order(:package, "advisories.advisory_id")
                        .pluck(:package, "advisories.advisory_id").group_by(&:first).transform_values { |rows| rows.map(&:last) }
  end

  def finding(host, package, advisory_id) = VulnerabilityFinding.with_details.joins(:advisory).find_by!(host:, package:, advisories: { advisory_id: })

  it "gives the running kernel's signed image and its metapackage linux's findings, and shim-signed shim's, which matching by the reported source never did" do
    host = debian_host(packages:)
    advisories
    before = SignedSources.table
    allow(SignedSources).to receive(:table).and_return({}) # main: matched by the reported source only
    match(host)
    expect(open_findings(host)).to eq("grub-common" => [ "DEBIAN-CVE-2026-91006" ], "grub-efi-amd64-bin" => [ "DEBIAN-CVE-2026-91006" ],
                                      "linux-headers-6.12.48+deb13-amd64" => %w[DEBIAN-CVE-2026-91001 DEBIAN-CVE-2026-91002],
                                      "linux-headers-6.12.48+deb13-common" => %w[DEBIAN-CVE-2026-91001 DEBIAN-CVE-2026-91002],
                                      "linux-libc-dev" => %w[DEBIAN-CVE-2026-91001 DEBIAN-CVE-2026-91002],
                                      "shim-unsigned" => [ "DEBIAN-CVE-2026-91004" ])

    allow(SignedSources).to receive(:table).and_return(before)
    VulnerabilityMatcher.match_again!
    expect(open_findings(host)).to include("linux-image-6.12.48+deb13-amd64" => %w[DEBIAN-CVE-2026-91001 DEBIAN-CVE-2026-91002],
                                           "linux-image-amd64" => %w[DEBIAN-CVE-2026-91001 DEBIAN-CVE-2026-91002],
                                           "shim-signed" => [ "DEBIAN-CVE-2026-91004" ])
    # Left out on purpose: shim-signed-common is not shim; shim-helpers-amd64-signed's version cannot be read back and
    # shim's findings are on shim-unsigned and shim-signed; grub2's advisories stay on grub-common, which the signed
    # image depends on at the same grub2 version; Debian lists nothing for fwupd-efi that would apply.
    expect(open_findings(host).keys).not_to include("shim-signed-common", "shim-helpers-amd64-signed", "grub-efi-amd64-signed", "fwupd-amd64-signed")
    expect(open_findings(host)).to include("shim-unsigned" => [ "DEBIAN-CVE-2026-91004" ])
    expect(finding(host, running[0], "DEBIAN-CVE-2026-91001"))
      .to have_attributes(source: "linux", installed_version: "6.12.48-1", fixed_version: "6.12.88-1", state: "open")
    expect(finding(host, "shim-signed", "DEBIAN-CVE-2026-91004")).to have_attributes(source: "shim", installed_version: shim[1], fixed_version: nil)
  end

  it "keeps the running kernel's findings open when only linux-libc-dev is upgraded, and moves them as the kernel is upgraded and the old one removed" do
    host = debian_host(packages:)
    advisories
    match(host)
    kernel = %w[DEBIAN-CVE-2026-91001 DEBIAN-CVE-2026-91002]

    report(host, packages.map { |p| p == libc ? [ "linux-libc-dev", "6.12.88-1", "linux" ] : p })
    match(host, at: now + 1.hour)
    expect(finding(host, "linux-libc-dev", "DEBIAN-CVE-2026-91001")).to have_attributes(state: "resolved", resolution: "fixed")
    expect(open_findings(host)).to include(running[0] => kernel, "linux-image-amd64" => kernel)

    # apt full-upgrade: a new image package beside the running one, and the metapackage moves to it.
    upgraded = packages.map { |p| p == meta ? [ "linux-image-amd64", "6.12.88-1", "linux-signed-amd64" ] : p } +
               [ [ "linux-image-6.12.88+deb13-amd64", "6.12.88-1", "linux-signed-amd64" ] ]
    report(host, upgraded)
    match(host, at: now + 2.hours)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91001")).to have_attributes(state: "resolved", resolution: "fixed", installed_version: "6.12.88-1")
    expect(open_findings(host)).to include(running[0] => kernel, "linux-image-6.12.88+deb13-amd64" => [ "DEBIAN-CVE-2026-91002" ])

    report(host, upgraded - [ running ]) # after the reboot, apt autoremove
    match(host, at: now + 3.hours)
    expect(finding(host, running[0], "DEBIAN-CVE-2026-91001")).to have_attributes(state: "resolved", resolution: "removed")
  end

  it "resolves a signed package's finding as fixed past the fix, and as not affected only when the advisory names neither of its sources" do
    host = debian_host(packages: [ running, meta ])
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91001", package: "linux", fixed: "6.12.88-1"),
                      osv_record(id: "DEBIAN-CVE-2026-91002", package: "linux", fixed: nil))
    match(host)
    report(host, [ running, [ "linux-image-amd64", "6.12.88-1", "linux-signed-amd64" ] ])
    match(host, at: now + 1.hour)
    expect(finding(host, "linux-image-amd64", "DEBIAN-CVE-2026-91001")).to have_attributes(state: "resolved", resolution: "fixed", source: "linux")

    # An advisory moved from linux to the signed source itself still names the image: it stays affected.
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91002", package: "linux-signed-amd64", fixed: nil, modified: "2026-11-01T00:00:00Z"))
    VulnerabilityMatcher.match_again!
    expect(finding(host, running[0], "DEBIAN-CVE-2026-91002")).to have_attributes(state: "open", source: "linux-signed-amd64")
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91002", package: "linux-6.1", fixed: nil, modified: "2026-11-02T00:00:00Z"))
    VulnerabilityMatcher.match_again!
    expect(finding(host, running[0], "DEBIAN-CVE-2026-91002")).to have_attributes(state: "resolved", resolution: "not_affected")
  end

  it "only adds: an advisory naming the signed source matches at the binary's version, and one naming both sources is one finding" do
    host = debian_host(packages: [ running, shim ])
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91008", package: "shim-signed", fixed: "1.52"), # reported source, binary version
                      osv_record(id: "DEBIAN-CVE-2026-91009", package: "linux", fixed: "6.12.88-1")
                        .tap { |r| r["affected"] << r["affected"].first.deep_merge("package" => { "name" => "linux-signed-amd64" }) })
    match(host)
    expect(open_findings(host)).to eq(running[0] => [ "DEBIAN-CVE-2026-91009" ], "shim-signed" => [ "DEBIAN-CVE-2026-91008" ])
    expect(finding(host, "shim-signed", "DEBIAN-CVE-2026-91008")).to have_attributes(source: "shim-signed", fixed_version: "1.52")
    expect(finding(host, running[0], "DEBIAN-CVE-2026-91009")).to have_attributes(source: "linux")
  end

  it "lists a shim-signed whose shim version cannot be read as not evaluated, with why" do
    host = debian_host(packages: [ [ "shim-signed", "1.32+15+1533136590.3beb971-5", "shim-signed" ] ])
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91005", package: "shim", fixed: "15.8-1"))
    match(host)
    expect(VulnerabilityFinding.where(host:)).to be_empty
    expect(HostVulnerabilityEvaluation.find_by!(host:).not_evaluated)
      .to eq([ { "package" => "shim-signed", "architecture" => "amd64", "version" => "1.32+15+1533136590.3beb971-5", "source" => "shim",
                 "advisory" => "DEBIAN-CVE-2026-91005",
                 "reason" => "the shim version built into shim-signed 1.32+15+1533136590.3beb971-5 cannot be read from it (shim-signed: <shim-signed version>+<shim version>)" } ])
  end

  it "re-matches a chunk holding only the signed image when linux's advisories change, and does not move its stamp past such an import" do
    host = debian_host(packages: [ running ])
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91003", package: "linux", fixed: "6.12.43-1"))
    match(host)
    first = AdvisoryImport.newest_succeeded_id
    expect(VulnerabilityFinding.where(host:)).to be_empty

    result = import_advisories(osv_record(id: "DEBIAN-CVE-2026-91001", package: "linux", fixed: "6.12.88-1"))
    expect(result.changed_packages).to eq("Debian:13" => [ "linux" ])
    expect(VulnerabilityMatcher::Chunks.restamp!(AdvisoryImport.newest_succeeded_id)).to eq(0) # its chunk holds no "linux" entry, but is linux's
    expect(ChunkEvaluation.pluck(:advisory_import_id).uniq).to eq([ first ])

    work = EvaluationRun::Advisories.new("packages" => result.changed_packages)
    work.prepare!
    expect(ChunkEvaluation.pluck(:advisory_import_id).uniq).to eq([ AdvisoryImport.newest_succeeded_id ])
    expect(work.hosts.pluck(:id)).to eq([ host.id ])
    expect(work.call(host.id..host.id)).to eq([ host.id ])
    expect(open_findings(host)).to eq(running[0] => [ "DEBIAN-CVE-2026-91001" ])
    expect(PackageSet.holding_sources([ "linux" ]).pluck(:id)).to eq([ HostPackageSet.find_by!(host:).package_set_id ])
  end
end
