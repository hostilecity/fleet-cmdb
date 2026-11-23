require "rails_helper"

# The Vulnerabilities tab says which packages are backports and how they are matched (#274, HostBackports). Package
# names follow Debian's (trixie-backports' linux 7.0.9-1~bpo13+1 and its signed image; the wireguard-tools version is
# illustrative); advisory ids are made up.
RSpec.describe "Backports on the Vulnerabilities tab", :signed_in, type: :request do
  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  let(:bpo) do
    [ [ "linux-image-7.0.9+deb13-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ], [ "linux-image-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ],
      [ "wireguard-tools", "1.0.20250521-1~bpo13+1", "wireguard" ], [ "openssl", "3.5.0-1", "openssl" ] ]
  end

  def linux(ecosystem) = osv_record(id: "DEBIAN-CVE-2026-91001", package: "linux", fixed: "6.12.95-1", ecosystem:)

  it "lists the host's backports, says they are matched against Debian 14 too, and names the sources its data has nothing for" do
    host = debian_host(packages: bpo)
    record = linux("Debian:13")
    record["affected"] << linux("Debian:14")["affected"].first
    import_advisories(record)
    VulnerabilityMatcher.match!([ host.id ])

    get "/hosts/#{host.id}/vulnerabilities"
    expect(response).to have_http_status(:ok)
    notice = page.at_css("#backports")
    expect(words(notice)).to start_with("3 backports on this host. Packages from the release's backports are built from Debian 14 (forky), so they are matched " \
                                        "against its advisories as well as this release's.")
    expect(words(notice)).to include("Debian 14 (forky)'s advisory data names nothing for wireguard , so what affects only the backport's series cannot be found for it.")
    expect(notice.css("#backport_list li").map { |li| words(li) })
      .to eq([ "linux-image-7.0.9+deb13-amd64:amd64 7.0.9-1~bpo13+1", "linux-image-amd64:amd64 7.0.9-1~bpo13+1", "wireguard-tools:amd64 1.0.20250521-1~bpo13+1" ])
    expect(notice.at_css("#backport_list a")["href"]).to eq("/hosts/#{host.id}/vulnerabilities/package?package=linux-image-7.0.9%2Bdeb13-amd64")
    expect(notice.text).not_to include("Showing the first")
  end

  it "says so for every source when Debian 14's data has none, and shows the first ones of many" do
    stub_const("HostBackports::LIMIT", 2)
    host = debian_host(packages: bpo)
    import_advisories(linux("Debian:13"))
    VulnerabilityMatcher.match!([ host.id ])
    get "/hosts/#{host.id}/vulnerabilities"
    notice = page.at_css("#backports")
    expect(words(notice)).to include("names nothing for linux , so what affects only the backport's series cannot be found for them.")
    expect(notice.css("#backport_list li").size).to eq(2)
    expect(words(notice)).to include("Showing the first 2.")
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
