require "rails_helper"

# POST /api/v1/reports/packages (P2-S08, FR-2.3, FR-S.2, DEC-07, AC-2.3)
RSpec.describe "POST /api/v1/reports/packages", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }
  let(:example) { ApiContract.example("packages.request", "dpkg") }

  def report(**overrides) = example.merge("report_id" => SecureRandom.uuid).merge(overrides.transform_keys(&:to_s))

  def send_report(payload, as: credential, headers: {}) = post_api("/api/v1/reports/packages", payload, as, headers:)

  def stored_packages = stored_package_rows(host).map { |row| AgentApi::PackageReport::Package.from_a(row).to_h.transform_keys(&:to_s) }

  def sorted(packages) = packages.sort_by { |p| [ p["name"], p["architecture"] ] }

  def gzip(text) = ActiveSupport::Gzip.compress(text)

  # The INSERT, UPDATE, and DELETE statements on the package store's tables that the block sends.
  def package_writes
    statements = []
    counter = ->(*, payload) { statements << payload[:sql] if payload[:sql].match?(/\A\s*(INSERT|UPDATE|DELETE)[^"]*"package_(chunks|chunk_entries|sets)"/) }
    ActiveSupport::Notifications.subscribed(counter, "sql.active_record") { yield }
    statements
  end

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

    it "stores only the chunks that changed: the others are the same rows, shared (ADR 0028)" do
      send_report(report)
      before = PackageSnapshot.find_by!(host:).package_set_id
      packages = example["packages"].reject { |p| p["name"] == "vim" }
                                    .map { |p| p["name"] == "openssl" ? p.merge("version" => "3.5.1-1+deb13u2") : p }
                                    .map { |p| p["name"] == "tzdata" ? p.merge("source" => "tzdata-legacy") : p }
      packages << { "name" => "curl", "version" => "8.14.1-2", "architecture" => "amd64", "source" => nil }

      statements = package_writes { send_report(report(packages:)) }

      expect(stored_packages).to eq(sorted(packages))
      after = PackageSnapshot.where(host:).chronological.last.package_set_id
      old_chunks, new_chunks = PackageSet.find(before).chunk_ids, PackageSet.find(after).chunk_ids
      buckets = %w[vim openssl tzdata tzdata-legacy curl].map { |source| PackageStore.bucket(source) }.uniq
      expect((0...64).reject { |b| old_chunks[b] == new_chunks[b] }).to match_array(buckets.select { |b| old_chunks[b] || new_chunks[b] })
      expect(statements.join).not_to include("libc6")
      expect(statements.grep(/INSERT INTO "package_chunk_entries"/).size).to eq(1) # one batch for the new chunks
    end

    it "stores nothing new when another host reports the same set" do
      send_report(report)
      other, other_credential = enrolled_host
      statements = package_writes { post_api("/api/v1/reports/packages", report, other_credential) }
      expect(statements).to eq([]) # the set is found by its hash
      expect(HostPackageSet.find_by!(host: other).package_set_id).to eq(HostPackageSet.find_by!(host:).package_set_id)
    end

    it "writes no package rows when only the skipped names changed" do
      send_report(report)
      statements = package_writes do
        expect { send_report(report(skipped: [ { "name" => "vim", "reason" => "unpacked" } ])) }.to change(PackageSnapshot, :count).by(1)
      end
      expect(statements).to eq([]) # no DELETE, and no upsert rewriting unchanged rows (review of #185)
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
      expect(PackageSnapshot.where(host:).chronological.last).to have_attributes(unsupported?: true, package_set_id: nil, package_list: [])
      expect(stored_packages).to be_empty
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
      expect(PackageSnapshot.where(host:).chronological.last).to have_attributes(unreadable?: true, package_set_id: nil, package_count: 0)
    end

    it "is recorded on a host that had never reported, with no packages" do
      send_report(unreadable)
      expect(HostPackageSet.find_by!(host:)).to have_attributes(manager: "unreadable", package_count: 0, package_set_id: nil)
      expect(stored_packages).to be_empty
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

  describe "review of #121" do
    def snapshots = PackageSnapshot.where(host:).chronological.to_a
    def vim = example["packages"].find { |p| p["name"] == "vim" }
    def without_vim = example["packages"].reject { |p| p["name"] == "vim" }
    def vim_skipped = [ { "name" => "vim", "reason" => "half-configured" } ]

    it "shows a package removed while it was skipped as removed, with the earlier reason and no version (comment 4503060857)" do
      send_report(report)
      send_report(report(packages: without_vim, "skipped" => vim_skipped))
      send_report(report(packages: without_vim))
      _, was_skipped, gone = snapshots
      expect(PackageDiff.for(was_skipped).skipped.map(&:name)).to eq([ "vim" ])
      diff = PackageDiff.for(gone)
      expect(diff.removed_skipped).to eq([ PackageDiff::SkippedRemoval.new(name: "vim", reason: "half-configured") ])
      expect(diff).to have_attributes(removed: [], installed: [], completed: [], skipped: [], empty?: false)
    end

    it "shows a package installed after it was skipped as a completed installation, not a plain install (comment 4503060857)" do
      send_report(report(packages: without_vim))
      send_report(report(packages: without_vim, "skipped" => vim_skipped))
      send_report(report)
      diff = PackageDiff.for(snapshots.last)
      expect(diff.installed).to eq([])
      expect(diff.completed.map { |c| [ c.name, c.architecture, c.package.version, c.reason ] }).to eq([ [ "vim", vim["architecture"], vim["version"], "half-configured" ] ])
      expect(diff.removed_skipped).to eq([])
    end

    it "shows nothing for a name skipped by both reports" do
      send_report(report(packages: without_vim, "skipped" => vim_skipped))
      send_report(report(packages: without_vim, "skipped" => [ { "name" => "vim", "reason" => "unpacked" } ]))
      expect(PackageDiff.for(snapshots.last)).to have_attributes(available?: true, empty?: true)
    end

    it "has no diff when every earlier snapshot kept is unreadable, and everything installed for the host's first (comment 4502986292)" do
      send_report(ApiContract.example("packages.request", "unreadable-manager").merge("report_id" => SecureRandom.uuid))
      send_report(report)
      first, readable = snapshots
      expect(readable.previous).to eq(first)
      expect(readable.previous_known).to be_nil
      expect(PackageDiff.for(readable)).to have_attributes(available?: false, unavailable_reason: PackageDiff::NO_KNOWN_BASELINE, installed: [])
      first.destroy # Retention pruning the unreadable one leaves the readable snapshot as the host's first kept
      expect(PackageDiff.for(readable.reload)).to have_attributes(available?: true, installed: have_attributes(size: 8))
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
    expect([ HostPackageSet.count, PackageSet.count, PackageSnapshot.count, PackageReportReceipt.count ]).to eq([ 0, 0, 0, 0 ])
  end

  it "stores a version dpkg would refuse as reported, so matching can mark it not evaluated (P2-S09)" do
    packages = [ example["packages"].first.merge("version" => "1.0-") ]
    send_report(report(packages:))
    expect(response).to have_http_status(:ok)
    expect(stored_package_rows(host).sole[2]).to eq("1.0-")
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
    expect([ stored_package_rows(host).size, diff.changed.size, diff.upgraded.size ]).to eq([ 3_000, 300, 300 ])
    timings = { first_report: stored - started, changed_report: changed - stored, diff: diffed - changed }
    Rails.logger.info("[package_reports_spec] 3,000 packages, #{first.to_json.bytesize} bytes (#{body.bytesize} gzip): #{timings.transform_values { |t| t.round(3) }}")
    expect(timings.values).to all(be < 5.0)
  end

  describe "what is in use (FR-2.6, #258)" do
    let(:scanned) { ApiContract.example("packages.request", "in-use-library-scan") }

    def stored = HostApplicability.find_by(host_id: host.id)

    it "stores listening packages by class, running services, unnamed listeners, and the scan, apart from the package set" do
      send_report(report)
      set_hash = HostPackageSet.find_by!(host:).content_hash
      in_use = scanned["in_use"].merge("listening" => scanned["in_use"]["listening"] + [ { "package" => "openssh-server", "class" => "network" } ])
      expect { send_report(report(in_use:)) }.not_to change(PackageSnapshot, :count)
      expect(response).to have_http_status(:ok)
      expect(HostPackageSet.find_by!(host:).content_hash).to eq(set_hash)
      expect(stored).to have_attributes(in_use_reported: true, listening_network: %w[openssh-server samba], listening_loopback: [],
                                        running_services: %w[cron openssh-server samba], unnamed_network: 1, unnamed_loopback: 0,
                                        library_scan: "ran", libraries: %w[libc6 libssl3t64], stale_libraries: [ "libssl3t64" ])
    end

    it "stores what listening processes load, each (package, listener, service) once, network if either entry is, sorted" do
      uses = scanned["in_use"]["loaded_by_listeners"]
      first = uses.first
      shuffled = uses.reverse + [ first.merge("class" => "network", "sockets" => [ "0.0.0.0:22/tcp" ]),
                                  { "package" => "libc6", "listener" => nil, "service" => nil, "class" => "loopback", "sockets" => [ "127.0.0.1:631/tcp" ] } ]
      send_report(report(in_use: scanned["in_use"].merge("loaded_by_listeners" => shuffled)))
      expect(response).to have_http_status(:ok)
      expect(stored.loaded_by_listeners).to eq([ { "package" => "libc6", "listener" => nil, "service" => nil, "class" => "loopback", "sockets" => [ "127.0.0.1:631/tcp" ] },
                                                 first.merge("class" => "network", "sockets" => first["sockets"] + [ "0.0.0.0:22/tcp" ]), *uses.drop(1) ])
      now = Time.iso8601("2026-01-01T12:00:00Z")
      expect(stored.in_use_by_listener?("libssl3t64", now:, network: true)).to be(true)
      expect(stored.listener_details("libssl3t64", now:)).to eq([ { "listener" => "samba", "service" => "smbd.service", "class" => "network",
                                                                    "sockets" => [ "0.0.0.0:445/tcp" ] } ])
    end

    it "writes only when what is in use changes" do
      send_report(report(in_use: scanned["in_use"]))
      changed_at = stored.in_use_changed_at
      writes = []
      counter = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\A\s*(INSERT|UPDATE)[^"]*"host_applicability"/) }
      ActiveSupport::Notifications.subscribed(counter, "sql.active_record") do
        travel(1.hour) { send_report(report(in_use: scanned["in_use"])) }
      end
      expect(writes).to eq([])
      expect(stored.in_use_changed_at).to eq(changed_at)
    end

    it "clears it when a report has none: an unreadable one, or one that could not read it" do
      send_report(report(in_use: scanned["in_use"]))
      expect(stored).to have_attributes(loaded_by_listeners: scanned["in_use"]["loaded_by_listeners"], library_scanned_at: Time.iso8601("2026-01-01T11:30:00Z"))
      send_report(ApiContract.example("packages.request", "unreadable-manager").merge("report_id" => SecureRandom.uuid))
      expect(stored.in_use_reported).to be(false) # review of #268, S1: old use data never looks current
      send_report(report(in_use: scanned["in_use"]))
      failed = ApiContract.example("packages.request", "in-use-unreadable")
      send_report(failed.merge("report_id" => SecureRandom.uuid))
      expect(stored).to have_attributes(in_use_reported: false, libraries: [], library_scan: nil)
      expect(HostPackageSet.find_by!(host:).warnings).to include("field" => "in_use", "message" => failed["warnings"][0]["message"])
    end

    it "refuses in_use with an unsupported package manager, and writes nothing" do
      payload = ApiContract.examples_for("packages.request", kind: "invalid").find { |e| e.name == "in-use-with-unsupported" }.data
      expect { send_report(payload.merge("report_id" => SecureRandom.uuid)) }.not_to change(HostApplicability, :count)
      expect_error(:bad_request, "validation_failed")
    end
  end
end
