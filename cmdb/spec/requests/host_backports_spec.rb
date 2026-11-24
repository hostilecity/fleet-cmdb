require "rails_helper"

# The Vulnerabilities tab says which packages are backports and how they are matched (#274, HostBackports), shows a
# fix only the release they are built from records as not counted, says which findings are kept open, and does not
# show Debian's triage for the host's release beside them (review S1). Package names follow Debian's (trixie-backports'
# linux 7.0.9-1~bpo13+1 and its signed image; the wireguard-tools and calibre versions are illustrative); advisory ids
# are made up except DEBIAN-CVE-2026-64253's fixes (6.12.95-1 in trixie, 7.1.3-1 in forky).
RSpec.describe "Backports on the Vulnerabilities tab", :signed_in, type: :request do
  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  let(:bpo) do
    [ [ "linux-image-7.0.9+deb13-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ], [ "linux-image-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ],
      [ "wireguard-tools", "1.0.20250521-1~bpo13+1", "wireguard" ], [ "openssl", "3.5.0-1", "openssl" ] ]
  end

  def both(id, package: "linux", trixie: "6.12.95-1", forky: "7.1.3-1", **)
    osv_record(id:, package:, fixed: trixie, **).tap do |r|
      r["affected"] << osv_record(id:, package:, fixed: forky, ecosystem: "Debian:14")["affected"].first unless forky == :absent
    end
  end

  it "lists the host's backports, says how they are matched, names the sources forky has nothing for, and shows forky's fix as not counted" do
    host = debian_host(packages: bpo)
    import_advisories(both("DEBIAN-CVE-2026-64253"), full: true, origin: "feed")
    VulnerabilityMatcher.match!([ host.id ])

    get "/hosts/#{host.id}/vulnerabilities"
    expect(response).to have_http_status(:ok)
    notice = page.at_css("#backports")
    expect(words(notice)).to start_with("3 backports on this host. They are built from Debian 14 (forky), so they are matched against its advisories as well " \
                                        "as this release's. A fix that only this release's data records is not counted for them, and neither is Debian's " \
                                        "triage for this release.")
    expect(words(page.at_css("#backports_uncovered"))).to eq("Debian 14 (forky)'s advisory data names nothing for wireguard , so what affects only the " \
                                                             "backport's series cannot be found for that source.")
    expect(page.at_css("#backports_kept")).to be_nil
    expect(notice.css("#backport_list li").map { |li| words(li) })
      .to eq([ "linux-image-7.0.9+deb13-amd64:amd64 7.0.9-1~bpo13+1", "linux-image-amd64:amd64 7.0.9-1~bpo13+1", "wireguard-tools:amd64 1.0.20250521-1~bpo13+1" ])
    expect(notice.at_css("#backport_list a")["href"]).to eq("/hosts/#{host.id}/vulnerabilities/package?package=linux-image-7.0.9%2Bdeb13-amd64")
    expect(notice.text).not_to include("Showing the first")

    get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "linux-image-amd64" }
    expect(page.text.squish).to include("Fixed in 7.1.3-1 in the release this backport is built from; no backport of it known yet")
  end

  it "says the data is not imported yet before a full import, and lists all sources forky has nothing for, past the first ones shown" do
    stub_const("HostBackports::LIMIT", 1)
    host = debian_host(packages: bpo)
    import_advisories(both("DEBIAN-CVE-2026-64253"))
    VulnerabilityMatcher.match!([ host.id ])
    get "/hosts/#{host.id}/vulnerabilities"
    expect(words(page.at_css("#backports_no_data"))).to start_with("Debian 14 (forky)'s advisory data, which they are built from, has not come with a full advisory import yet.")
    expect(page.at_css("#backports_uncovered")).to be_nil
    expect(words(page.at_css("#backports"))).to include("Showing the first 1.")

    import_advisories(both("DEBIAN-CVE-2026-64253", forky: :absent), both("DEBIAN-CVE-2026-91002", package: "openssl"), full: true, origin: "feed")
    get "/hosts/#{host.id}/vulnerabilities"
    expect(words(page.at_css("#backports_uncovered"))).to include("names nothing for linux , wireguard , so what affects only the backport's series cannot be found for those sources.")
  end

  it "says which findings are kept open, and shows neither Debian's triage for trixie beside a backport's finding nor counts it in the no-DSA chip" do
    host = debian_host(packages: [ [ "calibre", "8.16.2+ds+~0.10.5-3~bpo13+1", "calibre" ], [ "calibre-bin", "8.5.0+ds-1", "calibre" ] ])
    import_advisories(both("DEBIAN-CVE-2026-91020", package: "calibre", trixie: nil, forky: :absent),
                      both("DEBIAN-CVE-2026-91021", package: "calibre", trixie: nil, forky: :absent), both("DEBIAN-CVE-2026-64253"), full: true, origin: "feed")
    import_triage(tracker_document("calibre" => { "CVE-2026-91020" => { "trixie" => tracker_release(nodsa: "Minor issue") },
                                                  "CVE-2026-91021" => { "trixie" => tracker_release(nodsa: "Minor issue") } }))
    VulnerabilityMatcher.match!([ host.id ])
    import_advisories(both("DEBIAN-CVE-2026-91020", package: "calibre", trixie: "8.5.0+ds-1+deb13u2", forky: :absent, modified: "2026-11-01T00:00:00Z"))
    VulnerabilityMatcher.match!([ host.id ])

    get "/hosts/#{host.id}/vulnerabilities"
    expect(words(page.at_css("#backports_kept"))).to eq("1 open finding is kept open: no release's data says it is affected, but Debian 14 (forky) has no " \
                                                        "data for its source, so a fix another release's data records is no evidence for a backport. It is " \
                                                        "still triaged, and resolves when the package is removed, the advisory is withdrawn, or Debian 14 " \
                                                        "(forky)'s data names its source.")
    expect(page.text.squish).to include("Kept open: no release's data says it is affected, but a release this backport can be built from has no data for calibre")
    # calibre-bin is trixie's own package: its no-DSA note counts (2 advisories); the backport's two do not.
    expect(page.at_css("#triage_filter a").text.squish).to eq("Debian: no security update planned 2")
    get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "calibre" }
    expect(page.text.squish).to include("Debian's triage for trixie is about its own package, not this backport, so it is not shown or used.")
  end

  it "says when the last full import skipped Debian 14 entries, and Data sources shows forky's state (review S2)" do
    host = debian_host(packages: bpo)
    get "/data-sources"
    expect(words(page.at_css("#backports_data"))).to start_with("Backports. Debian:14 (Debian 14 (forky)) is kept only to match Debian 13 (trixie)'s backports. Not complete yet")
    bad = both("DEBIAN-CVE-2026-91030").tap { |r| r["affected"].last["package"]["name"] = "Bad Name" }
    import_advisories(both("DEBIAN-CVE-2026-64253"), bad, full: true, origin: "feed")
    VulnerabilityMatcher.match!([ host.id ])
    get "/hosts/#{host.id}/vulnerabilities"
    expect(words(page.at_css("#backports_skipped"))).to eq("The last full import skipped 1 malformed entry of Debian 14 (forky)'s data, so findings that rest on it can be missing. See Data sources .")
    get "/data-sources"
    expect(words(page.at_css("#backports_data"))).to match(/Complete since the full import of .+, which skipped 1 malformed Debian:14 entry\.\z/)
  end

  describe "Debian 14's freshness and a release that never comes (#304)", withdrawal_guard: { share: 1.0, min_records: 0 } do
    let(:trixie_only) { osv_record(id: "DSA-9101-1", package: "openssl", fixed: "3.5.1-1+deb13u1") }

    # As if the imports so far had finished that long ago (a signed-in session does not survive travel).
    def age_imports(by) = AdvisoryImport.update_all([ "finished_at = finished_at - ?::interval", "#{by.to_i} seconds" ])

    def row(id) = page.at_css("#freshness_#{id}").css("td").map { |td| words(td) }

    it "shows Debian 14 and Debian 15 in the freshness table, and says when full imports arrive without Debian 14" do
      host = debian_host(packages: bpo)
      get "/data-sources"
      expect(row("debian_14")).to eq([ "Debian:14 Debian 14 (forky): used for Debian 13 (trixie)'s backports", "Never imported", "Never", "0 current 0 withdrawn", "Backports only" ])
      expect(row("debian_15")).to eq([ "Debian:15 Debian 15 (duke): used for Debian 13 (trixie)'s backports-sloppy builds", "Not published yet", "Never", "0 current 0 withdrawn", "Backports only" ])
      expect(words(page.at_css("#backports_sloppy_data"))).to start_with("Backports-sloppy. Debian:15 (Debian 15 (duke)) is kept only to match Debian 13 (trixie)'s " \
                                                                         "backports-sloppy builds, which Debian makes from the testing release once Debian 14 (forky) is released.")
      expect(words(page.at_css("#backports_sloppy_data"))).to end_with("No full import has kept it yet. OSV publishes it once that release is testing; until then backports are matched without it.")

      import_advisories(trixie_only, full: true, origin: "feed") # an archive with no Debian:14
      VulnerabilityMatcher.match!([ host.id ])
      get "/data-sources"
      expect(row("debian_14")[1]).to eq("Not in the imported archive")
      expect(words(page.at_css("#backports_data"))).to match(/Never complete: the full imports so far had none of it \(the last at .+\), so the archive the server imports does not have it/)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#backports_no_data"))).to start_with("Debian 14 (forky)'s advisory data, which they are built from, is not in the archive the server imports: the last full import")
    end

    it "shows Debian 14 fresh, then stale on Data sources and the tab, and says when it stopped coming" do
      host = debian_host(packages: bpo)
      import_advisories(trixie_only, both("DEBIAN-CVE-2026-64253"), full: true, origin: "feed")
      VulnerabilityMatcher.match!([ host.id ])
      get "/data-sources"
      expect(row("debian_14")[1..3]).to match([ "Fresh", /\A\d{4}-\d\d-\d\d \d\d:\d\d UTC/, "1 current 0 withdrawn" ])
      expect(row("debian_15")[1]).to eq("Not published yet")
      get "/hosts/#{host.id}/vulnerabilities"
      expect(page.at_css("#backports_stale")).to be_nil

      age_imports(Advisories.config.max_age + 1.hour)
      import_advisories(trixie_only, both("DEBIAN-CVE-2026-64253", forky: :absent), full: true, origin: "feed") # Debian:13 keeps coming, forky's not
      get "/data-sources"
      expect(row("debian_14")[1]).to eq("Not in the last full import")
      expect(words(page.at_css("#backports_data"))).to match(/The full imports since have none of it \(the last at .+\): the archive the server imports no longer has it\. Its last known data is kept/)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#backports_stale"))).to match(/\ADebian 14 \(forky\)'s advisory data was last updated .+, which is older than 48 hours, and it is not in the full imports since \(the last at .+\): the archive the server imports no longer has it, so its last known data is kept\. They are matched on old data, so findings can be missing\./)
      expect(page.at_css("#backports_stale a")["href"]).to eq("/data-sources#backports_data")
    end

    it "warns for Debian 15 once the tracker lists it and full imports lack it, and shows each release's skipped entries on the tab (review N2, N3)" do
      host = debian_host(packages: bpo)
      import_advisories(trixie_only, both("DEBIAN-CVE-2026-64253"), full: true, origin: "feed")
      import_triage(tracker_document("linux" => { "CVE-2027-90100" => { "duke" => tracker_release(repositories: { "duke" => "7.6.4-1" }) } }))
      get "/data-sources"
      expect(row("debian_15")[1]).to eq("Not in the imported archive")
      expect(words(page.at_css("#backports_sloppy_data"))).to match(/Never complete: the security tracker lists Debian 15 \(duke\), so OSV publishes its data, but the full imports so far had none of it/)

      bad = both("DEBIAN-CVE-2027-90110").tap { |r| r["affected"] << osv_record(id: "DEBIAN-CVE-2027-90110", package: "Bad Name", fixed: "1", ecosystem: "Debian:15")["affected"].first }
      import_advisories(trixie_only, both("DEBIAN-CVE-2026-64253"), bad,
                        both("DEBIAN-CVE-2027-90111").tap { |r| r["affected"] << osv_record(id: "DEBIAN-CVE-2027-90111", fixed: "7.6.4-1", package: "linux", ecosystem: "Debian:15")["affected"].first },
                        full: true, origin: "feed")
      VulnerabilityMatcher.match!([ host.id ])
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#backports_skipped_debian_15"))).to eq("The last full import skipped 1 malformed entry of Debian 15 (duke)'s data, so findings that rest on it can be missing. See Data sources .")
      expect(page.at_css("#backports_skipped_debian_15 a")["href"]).to eq("/data-sources#backports_sloppy_data")
      expect(page.at_css("#backports_skipped")).to be_nil, words(page.at_css("#backports_skipped") || page.root)
      get "/data-sources"
      expect(words(page.at_css("p.muted.small"))).to end_with("A release kept only for backports is flagged here and on the Vulnerabilities tab of hosts with backports.")
    end

    it "says in a kept finding's Fixed in cell why it is open, whichever release lacks data (review S3)" do
      host = debian_host(packages: [ [ "calibre", "8.16.2+ds+~0.10.5-3~bpo13+1", "calibre" ] ])
      import_advisories(both("DEBIAN-CVE-2026-91020", package: "calibre", trixie: nil, forky: :absent), both("DEBIAN-CVE-2026-64253"), full: true, origin: "feed")
      VulnerabilityMatcher.match!([ host.id ])
      import_advisories(both("DEBIAN-CVE-2026-91020", package: "calibre", trixie: "8.5.0+ds-1+deb13u2", forky: :absent, modified: "2026-11-01T00:00:00Z"))
      VulnerabilityMatcher.match!([ host.id ])
      get "/hosts/#{host.id}/vulnerabilities/package", params: { package: "calibre" }
      expect(page.text.squish).to include(HostVulnerabilitiesHelper::KEPT_OPEN)
    end

    it "matches against both releases once Debian 15's data is complete, and says which names nothing for a source" do
      host = debian_host(packages: bpo)
      duke = both("DEBIAN-CVE-2027-90009").tap { |r| r["affected"] << osv_record(id: "DEBIAN-CVE-2027-90009", package: "wireguard", fixed: "1.0.20260101-1", ecosystem: "Debian:15")["affected"].first }
      import_advisories(duke, full: true, origin: "feed")
      VulnerabilityMatcher.match!([ host.id ])
      get "/hosts/#{host.id}/vulnerabilities"
      expect(words(page.at_css("#backports"))).to include("They are built from Debian 14 (forky) or Debian 15 (duke), so they are matched against their advisories as well as this release's.")
      expect(words(page.at_css("#backports_uncovered"))).to eq("Debian 14 (forky)'s advisory data names nothing for wireguard , so what affects only the backport's series cannot be found for that source.")
      expect(words(page.at_css("#backports_uncovered_debian_15"))).to start_with("Debian 15 (duke)'s advisory data names nothing for linux ,")
      age_imports(Advisories.config.max_age + 1.hour)
      get "/hosts/#{host.id}/vulnerabilities"
      expect(page.at_css("#backports_stale_debian_15 a")["href"]).to eq("/data-sources#backports_sloppy_data") # review of #309, N3
      get "/data-sources"
      expect(row("debian_15")[1]).to eq("Stale: older than 48 hours")
      expect(words(page.at_css("#backports_sloppy_data"))).to match(/Complete since the full import of .+\. It is stale, so backports are matched on old data/)
    end
  end

  it "says a K1 backports finding's fix is installed, as its reason does (review S3)" do
    host = debian_host(packages: [ bpo[0], [ "linux-image-7.3.4+deb13-amd64", "7.3.4-1~bpo13+1", "linux-signed-amd64" ] ])
    record_inventory(host, kernel_version: "7.0.9+deb13-amd64")
    import_advisories(both("DEBIAN-CVE-2026-64253"), full: true, origin: "feed")
    VulnerabilityMatcher.match!([ host.id ])
    get "/hosts/#{host.id}/vulnerabilities/package", params: { package: bpo[0][0] }
    expect(page.text.squish).to include("Fixed in 7.1.3-1, which is installed (a backport at or above it)")
  end

  it "shows no notice on a host with no backport, or one not evaluated" do
    host = debian_host(packages: [ [ "openssl", "3.5.0-1", "openssl" ] ])
    import_advisories(osv_record(id: "DSA-9001-1"))
    VulnerabilityMatcher.match!([ host.id ])
    get "/hosts/#{host.id}/vulnerabilities"
    expect(page.at_css("#backports")).to be_nil

    other = debian_host(packages: bpo, os: { "id" => "debian", "version_id" => "12" })
    VulnerabilityMatcher.match!([ other.id ])
    get "/hosts/#{other.id}/vulnerabilities"
    expect(page.at_css("#backports")).to be_nil
    expect(HostBackports.new("Debian:12", 1)).not_to be_any
    expect(HostBackports.new("Debian:13", nil)).not_to be_any
  end
end
