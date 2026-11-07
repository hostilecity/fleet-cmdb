require "rails_helper"

# POST /api/v1/reports/packages (P2-S08, FR-2.3, FR-S.2, DEC-07, AC-2.3)
RSpec.describe "POST /api/v1/reports/packages", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }
  let(:example) { ApiContract.example("packages.request", "dpkg") }

  def report(**overrides) = example.merge("report_id" => SecureRandom.uuid).merge(overrides.transform_keys(&:to_s))

  def send_report(payload, as: credential, headers: {}) = post_api("/api/v1/reports/packages", payload, as, headers:)

  def stored_packages = HostPackage.where(host:).order(:name, :architecture).map { |p| p.to_package.to_h.transform_keys(&:to_s) }

  def sorted(packages) = packages.sort_by { |p| [ p["name"], p["architecture"] ] }

  def gzip(text) = ActiveSupport::Gzip.compress(text)

  it "stores the reported set exactly, with no package added or missing, and its first snapshot (AC-2.3)" do
    payload = report
    send_report(payload)
    expect(response).to have_http_status(:ok)
    expect(json).to eq("report_id" => payload["report_id"], "duplicate" => false)
    expect(ApiContract.errors("packages.response", "v1", json)).to eq([])

    expect(stored_packages).to eq(sorted(payload["packages"]))
    expect(stored_packages.map { |p| [ p["name"], p["architecture"] ] }).to include([ "libc6", "amd64" ], [ "libc6", "i386" ])
    expect(stored_packages.find { |p| p["name"] == "local-tool" }["source"]).to be_nil

    set = HostPackageSet.find_by!(host:)
    expect(set).to have_attributes(manager: "dpkg", unsupported_reason: nil, package_count: 8, report_id: payload["report_id"], warnings: [])
    snapshot = PackageSnapshot.find_by!(host:)
    expect(snapshot.package_list.map { |p| p.to_h.transform_keys(&:to_s) }).to eq(sorted(payload["packages"]))
    expect(snapshot).to have_attributes(content_hash: set.content_hash, package_count: 8)
  end

  describe "idempotency and snapshots (DEC-07)" do
    it "answers a retried report as a duplicate and changes nothing" do
      payload = report
      send_report(payload)
      before = [ HostPackageSet.find_by!(host:).attributes, stored_packages, PackageSnapshot.count, PackageReportReceipt.count ]
      send_report(payload.merge("packages" => [])) # same report id, even with different contents
      expect(json).to eq("report_id" => payload["report_id"], "duplicate" => true)
      expect([ HostPackageSet.find_by!(host:).attributes, stored_packages, PackageSnapshot.count, PackageReportReceipt.count ]).to eq(before)
    end

    it "creates no snapshot for the same set listed in another order, but records the report and its warnings" do
      send_report(report)
      warnings = [ { "field" => "packages", "message" => "skipped \u0007an entry" } ]
      later = report(packages: example["packages"].reverse, warnings:)
      expect { send_report(later) }.not_to change(PackageSnapshot, :count)
      expect(HostPackageSet.find_by!(host:)).to have_attributes(report_id: later["report_id"], warnings: [ { "field" => "packages", "message" => "skipped an entry" } ])
    end

    it "snapshots a changed set, replaces the current packages, and diffs installs, removals, and upgrades (AC-2.3)" do
      send_report(report)
      packages = example["packages"].reject { |p| p["name"] == "vim" }
                                    .map { |p| p["name"] == "openssl" ? p.merge("version" => "3.5.1-1+deb13u2") : p }
      packages << { "name" => "curl", "version" => "8.14.1-2", "architecture" => "amd64", "source" => "curl" }
      send_report(report(packages:))

      expect(stored_packages).to eq(sorted(packages))
      first, second = PackageSnapshot.where(host:).chronological.to_a
      diff = PackageDiff.for(second)
      expect(diff.installed.map(&:name)).to eq([ "curl" ])
      expect(diff.removed.map(&:name)).to eq([ "vim" ])
      expect(diff.changed.map { |c| [ c.name, c.from.version, c.to.version, c.direction ] }).to eq([ [ "openssl", "3.5.1-1+deb13u1", "3.5.1-1+deb13u2", :upgrade ] ])
      expect(PackageDiff.for(first).installed.size).to eq(8)
    end
  end

  describe "an unsupported package manager" do
    let(:unsupported) { ApiContract.example("packages.request", "unsupported-manager").merge("report_id" => SecureRandom.uuid) }

    it "is recorded as unsupported with its reason, never as an empty set, and clears packages reported before" do
      send_report(report)
      send_report(unsupported)
      expect(response).to have_http_status(:ok)
      expect(HostPackageSet.find_by!(host:)).to have_attributes(manager: "unsupported", unsupported?: true, package_count: 0,
                                                                unsupported_reason: unsupported["unsupported_reason"])
      expect(PackageSnapshot.where(host:).chronological.last).to have_attributes(unsupported?: true, packages: [])
      expect(HostPackage.where(host:)).to be_empty
    end

    it "makes the diff to and from an unsupported manager unavailable, not everything removed or installed (review of #98)" do
      send_report(report)
      send_report(unsupported)
      send_report(report)
      first, to_unsupported, back = PackageSnapshot.where(host:).chronological.to_a
      [ PackageDiff.for(to_unsupported), PackageDiff.for(back) ].each do |diff|
        expect(diff).to have_attributes(available?: false, unavailable_reason: PackageDiff::UNAVAILABLE, installed: [], removed: [], changed: [])
      end
      expect(PackageDiff.for(first)).to have_attributes(available?: true, unavailable_reason: nil)
      expect(PackageDiff.between(first, back)).to have_attributes(available?: true, empty?: true)
    end

    it "is refused with packages, or without a reason" do
      send_report(unsupported.merge("packages" => example["packages"]))
      expect_error(:bad_request, "validation_failed")
      send_report(unsupported.merge("unsupported_reason" => nil))
      expect_error(:bad_request, "validation_failed")
      expect(HostPackageSet.count).to eq(0)
    end
  end

  describe "an unreadable package database (P2-S08, FR-2.3)" do
    let(:unreadable) { ApiContract.example("packages.request", "unreadable-manager").merge("report_id" => SecureRandom.uuid) }

    it "is recorded as unreadable with its reason, keeping the packages and count reported before" do
      send_report(report)
      kept = stored_packages
      send_report(unreadable)
      expect(response).to have_http_status(:ok)
      expect(HostPackageSet.find_by!(host:)).to have_attributes(manager: "unreadable", unreadable?: true, unsupported?: false, package_count: 8,
                                                                unsupported_reason: unreadable["unsupported_reason"])
      expect(stored_packages).to eq(kept)
      expect(PackageSnapshot.where(host:).chronological.last).to have_attributes(unreadable?: true, packages: [], package_count: 0)
    end

    it "is recorded on a host that had never reported, with no packages" do
      send_report(unreadable)
      expect(HostPackageSet.find_by!(host:)).to have_attributes(manager: "unreadable", package_count: 0)
      expect(HostPackage.where(host:)).to be_empty
    end

    it "snapshots a change of reason, and not the same unreadable report again" do
      send_report(report)
      send_report(unreadable)
      expect { send_report(unreadable.merge("report_id" => SecureRandom.uuid)) }.not_to change(PackageSnapshot, :count)
      expect { send_report(unreadable.merge("report_id" => SecureRandom.uuid, "unsupported_reason" => "dpkg-query was killed")) }.to change(PackageSnapshot, :count).by(1)
    end

    it "makes the diff of an unreadable snapshot unavailable, and compares what follows with the set before it" do
      send_report(report)
      send_report(unreadable)
      later = example["packages"].reject { |p| p["name"] == "vim" }
      send_report(report(packages: later))
      first, unreadable_snapshot, back = PackageSnapshot.where(host:).chronological.to_a
      expect(PackageDiff.for(unreadable_snapshot)).to have_attributes(available?: false, unavailable_reason: PackageDiff::UNREADABLE, installed: [], removed: [])
      expect(PackageDiff.between(first, unreadable_snapshot).unavailable_reason).to eq(PackageDiff::UNREADABLE)
      expect(unreadable_snapshot.previous).to eq(first)
      expect(back.previous).to eq(unreadable_snapshot)
      expect(back.previous_known).to eq(first)
      expect(PackageDiff.for(back)).to have_attributes(available?: true, removed: [ have_attributes(name: "vim") ])
    end

    it "is refused with packages or skipped names, or without a reason" do
      send_report(unreadable.merge("packages" => example["packages"]))
      expect_error(:bad_request, "validation_failed")
      send_report(unreadable.merge("unsupported_reason" => nil))
      expect_error(:bad_request, "validation_failed")
      send_report(unreadable.merge("skipped" => [ { "name" => "vim", "reason" => "unpacked" } ]))
      expect_error(:bad_request, "validation_failed")
      expect(HostPackageSet.count).to eq(0)
    end

    it "refuses a dpkg report that carries a reason" do
      send_report(report("unsupported_reason" => "dpkg-query failed"))
      expect_error(:bad_request, "validation_failed")
    end
  end

  describe "skipped packages (P2-S08, FR-2.3)" do
    let(:skipped_example) { ApiContract.example("packages.request", "skipped-packages").merge("report_id" => SecureRandom.uuid) }

    it "stores them, sorted, with the set and its snapshot, and keeps them out of the installed packages" do
      skipped = [ { "name" => "vim", "reason" => "unpacked" }, { "name" => "libssl3t64", "reason" => "half-configured" }, { "name" => "vim", "reason" => "unpacked" } ]
      send_report(skipped_example.merge("skipped" => skipped))
      expect(response).to have_http_status(:ok)
      expected = [ { "name" => "libssl3t64", "reason" => "half-configured" }, { "name" => "vim", "reason" => "unpacked" } ]
      expect(HostPackageSet.find_by!(host:)).to have_attributes(skipped: expected, package_count: 1)
      expect(PackageSnapshot.find_by!(host:).skipped).to eq(expected)
      expect(PackageSnapshot.find_by!(host:).skipped_list.map(&:to_h)).to eq(expected)
      expect(HostPackageSet.find_by!(host:).skipped_list.map(&:name)).to eq(%w[libssl3t64 vim])
      expect(stored_packages.map { |p| p["name"] }).to eq([ "base-files" ])
    end

    it "removes control characters from a reason, and keeps markup as text for the views to escape" do
      send_report(skipped_example.merge("skipped" => [ { "name" => "vim", "reason" => "<script>alert(1)</script>\u0007" } ]))
      expect(response).to have_http_status(:ok)
      expect(HostPackageSet.find_by!(host:).skipped.first["reason"]).to eq("<script>alert(1)</script>")
    end

    it "treats a report without skipped packages as it always did: the same hash, and no new snapshot" do
      payload = report
      send_report(payload)
      expect(HostPackageSet.find_by!(host:).skipped).to eq([])
      expect(HostPackageSet.find_by!(host:).content_hash).to eq(OpenSSL::Digest::SHA256.hexdigest(JSON.generate([ "dpkg", nil, AgentApi::PackageReport.new(payload).packages.map(&:to_a) ])))
      expect { send_report(report.merge("skipped" => [])) }.not_to change(PackageSnapshot, :count)
    end

    it "snapshots a change of the skipped names alone, and clears them when the next report has none" do
      send_report(report)
      expect { send_report(report("skipped" => [ { "name" => "vim", "reason" => "unpacked" } ])) }.to change(PackageSnapshot, :count).by(1)
      expect(HostPackageSet.find_by!(host:).skipped).to eq([ { "name" => "vim", "reason" => "unpacked" } ])
      expect { send_report(report) }.to change(PackageSnapshot, :count).by(1)
      expect(HostPackageSet.find_by!(host:).skipped).to eq([])
    end

    it "shows a package that is absent and named as skipped as skipped, not removed, and a still absent one as removed (AC-2.3)" do
      send_report(report)
      packages = example["packages"].reject { |p| %w[vim openssl].include?(p["name"]) }
      send_report(report(packages:, "skipped" => [ { "name" => "vim", "reason" => "half-configured" }, { "name" => "never-installed", "reason" => "unpacked" } ]))
      diff = PackageDiff.for(PackageSnapshot.where(host:).chronological.last)
      expect(diff.skipped.map { |s| [ s.name, s.architecture, s.reason, s.package.version ] }).to eq([ [ "vim", "amd64", "half-configured", example["packages"].find { |p| p["name"] == "vim" }["version"] ] ])
      expect(diff.removed.map(&:name)).to eq([ "openssl" ])
      expect(diff.installed).to eq([])
      expect(diff).to have_attributes(available?: true, empty?: false)
    end

    it "is refused with more than 64 names, an unreadable name, or no reason" do
      names = Array.new(65) { |i| { "name" => "pkg#{i}", "reason" => "unpacked" } }
      send_report(report("skipped" => names))
      expect_error(:bad_request, "validation_failed")
      send_report(report("skipped" => names.first(64)))
      expect(response).to have_http_status(:ok)
      send_report(report("skipped" => [ { "name" => "Vim", "reason" => "unpacked" } ]))
      expect_error(:bad_request, "validation_failed")
      send_report(report("skipped" => [ { "name" => "vim" } ]))
      expect_error(:bad_request, "validation_failed")
      send_report(report("skipped" => [ { "name" => "vim", "reason" => "x" * 129 } ]))
      expect_error(:bad_request, "validation_failed")
    end
  end

  it "refuses a package listed twice for the same architecture, and writes nothing" do
    packages = example["packages"] + [ example["packages"].first.merge("version" => "0.1") ]
    send_report(report(packages:))
    expect_error(:bad_request, "validation_failed")
    expect(json.dig("error", "details")).to eq([ { "pointer" => "/packages/8", "problem" => "duplicates an earlier package with the same name and architecture" } ])
    expect([ HostPackageSet.count, HostPackage.count, PackageSnapshot.count, PackageReportReceipt.count ]).to eq([ 0, 0, 0, 0 ])
  end

  it "stores a version dpkg would refuse as reported, so matching can mark it not evaluated (P2-S09)" do
    packages = [ example["packages"].first.merge("version" => "1.0-") ]
    send_report(report(packages:))
    expect(response).to have_http_status(:ok)
    expect(HostPackage.find_by!(host:).version).to eq("1.0-")
  end

  it "round-trips names and versions dpkg takes with only a warning, such as an underscore (review of #98)" do
    payload = ApiContract.example("packages.request", "unusual-names-and-versions").merge("report_id" => SecureRandom.uuid)
    send_report(payload)
    expect(response).to have_http_status(:ok)
    expect(stored_packages).to eq(sorted(payload["packages"]))
    expect(payload["packages"].map { |p| PackageVersions::Dpkg.valid?(p["version"]) }).to eq([ true, true, false ])
  end

  describe "size limits (review of #98)" do
    def padded(bytes) = report.merge("padding" => "a" * bytes).to_json # an unknown field: ignored and logged

    it "takes an uncompressed report past the general 1 MiB limit, up to the endpoint's 4 MiB, and refuses a larger one" do
      send_report(padded(1.5.megabytes))
      expect(response).to have_http_status(:ok)
      send_report(padded(4.megabytes))
      expect_error(:content_too_large, "payload_too_large")
    end

    it "holds a compressed report to 1 MiB on the wire, even when it would expand to less than 4 MiB" do
      body = gzip(report.merge("padding" => Base64.strict_encode64(SecureRandom.random_bytes(1_200_000))).to_json)
      expect(body.bytesize).to be > 1.megabyte
      send_report(body, headers: { "Content-Encoding" => "gzip" })
      expect_error(:content_too_large, "payload_too_large")
      expect(PackageReportReceipt.count).to eq(0)
    end
  end

  describe "gzip bodies" do
    it "accepts a gzip-compressed report" do
      payload = report
      send_report(gzip(payload.to_json), headers: { "Content-Encoding" => "gzip" })
      expect(json).to eq("report_id" => payload["report_id"], "duplicate" => false)
      expect(stored_packages).to eq(sorted(payload["packages"]))
    end

    it "refuses a body that is not gzip, a gzip body that expands beyond the limit, and other encodings" do
      send_report("not gzip", headers: { "Content-Encoding" => "gzip" })
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "message")).to eq("The request body is not valid gzip.")

      bomb = gzip(report(unsupported_reason: nil).to_json.sub("}", %(,"padding":"#{'a' * 5.megabytes}"}))) # about 5 KB compressed
      expect(bomb.bytesize).to be < 64.kilobytes
      send_report(bomb, headers: { "Content-Encoding" => "gzip" })
      expect_error(:content_too_large, "payload_too_large")

      send_report(report.to_json, headers: { "Content-Encoding" => "br" })
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "message")).to eq("The request body's Content-Encoding is not supported (use gzip or none).")
      expect(PackageReportReceipt.count).to eq(0)
    end

    it "is accepted only where an endpoint allows it" do
      post_api("/api/v1/heartbeat", gzip({ schema_version: 1 }.to_json), credential, headers: { "Content-Encoding" => "gzip" })
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "message")).to eq("The request body's Content-Encoding is not supported.")
    end
  end

  it "takes reports only from active hosts with a valid credential" do
    send_report(report, as: nil)
    expect_error(:unauthorized, "unauthorized")
    host.revoke!(actor: Audit::SYSTEM)
    send_report(report)
    expect_error(:unauthorized, "unauthorized")
    expect(PackageReportReceipt.count).to eq(0)
  end

  it "stores and diffs a realistic 3,000-package report in reasonable time (P2-S08)" do
    packages = Array.new(3_000) do |i|
      { "name" => format("pkg-%04d", i), "version" => "1:#{i % 50}.#{i % 7}.#{i}-#{i % 3 + 1}+deb13u#{i % 4}", "architecture" => i.even? ? "amd64" : "all",
        "source" => format("src-%04d", i / 3) }
    end
    first = report(packages:)
    second = report(packages: packages.each_with_index.map { |p, i| (i % 10).zero? ? p.merge("version" => "#{p['version']}.1") : p })
    body = gzip(first.to_json)

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    send_report(body, headers: { "Content-Encoding" => "gzip" })
    stored = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    send_report(second)
    changed = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    diff = PackageDiff.for(PackageSnapshot.where(host:).chronological.last)
    diffed = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    expect(response).to have_http_status(:ok)
    expect([ HostPackage.where(host:).count, diff.changed.size, diff.upgraded.size ]).to eq([ 3_000, 300, 300 ])
    timings = { first_report: stored - started, changed_report: changed - stored, diff: diffed - changed }
    Rails.logger.info("[package_reports_spec] 3,000 packages, #{first.to_json.bytesize} bytes (#{body.bytesize} gzip): #{timings.transform_values { |t| t.round(3) }}")
    expect(timings.values).to all(be < 5.0)
  end
end
