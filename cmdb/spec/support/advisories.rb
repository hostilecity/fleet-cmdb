# Helpers for advisory specs (P2-VULNS). spec/fixtures/osv holds hand-written OSV records in the shape osv.dev
# publishes for Debian; their ids, CVE numbers, versions, and URLs are made up (example.org stands in for
# the Debian security tracker), and malformed.json is deliberately cut short.
module AdvisoryHelpers
  OSV_FIXTURES = Rails.root.join("spec/fixtures/osv")

  # A minimal OSV record affecting package in Debian:13 between introduced and fixed (nil: not fixed).
  def osv_record(id: "DSA-#{rand(1000..9999)}-1", package: "openssl", fixed: "3.5.1-1+deb13u1", introduced: "0",
                 modified: "2026-10-20T08:00:00Z", ecosystem: "Debian:13", **extra)
    events = [ { "introduced" => introduced }, (fixed && { "fixed" => fixed }) ].compact
    { "id" => id, "modified" => modified,
      "affected" => [ { "package" => { "ecosystem" => ecosystem, "name" => package }, "ranges" => [ { "type" => "ECOSYSTEM", "events" => events } ] } ] }
      .merge(extra.transform_keys(&:to_s))
  end

  # A directory of the given records (Hashes, written as JSON, or Strings, written as they are), one file each.
  def osv_directory(*records)
    dir = Pathname(Dir.mktmpdir("osv-"))
    @osv_dirs = [ *@osv_dirs, dir ]
    records.each_with_index do |record, i|
      name = record.is_a?(Hash) ? record["id"] || "record-#{i}" : "record-#{i}"
      dir.join("#{name}.json").write(record.is_a?(Hash) ? JSON.generate(record) : record)
    end
    dir
  end

  # A zip archive like OSV's all.zip: entries is { "name.json" => record Hash or String }.
  def osv_zip(entries)
    path = Pathname(Dir.mktmpdir("osv-zip-")).join("all.zip")
    @osv_dirs = [ *@osv_dirs, path.dirname ]
    Zip::File.open(path.to_s, create: true) do |zip|
      entries.each { |name, record| zip.get_output_stream(name) { |io| io.write(record.is_a?(Hash) ? JSON.generate(record) : record) } }
    end
    path
  end

  # Stores a dpkg package report for an enrolled host through PackageRecorder, as the endpoint does. packages:
  # [[name, version, source], ...] (amd64), or full Hashes.
  def report_packages(host, packages, manager: "dpkg", unsupported_reason: nil, skipped: nil)
    list = packages.map { |p| p.is_a?(Hash) ? p : { "name" => p[0], "version" => p[1], "architecture" => p[3] || "amd64", "source" => p[2] } }
    payload = { "report_id" => SecureRandom.uuid, "schema_version" => 1, "collected_at" => Time.current.utc.iso8601, "manager" => manager,
                "unsupported_reason" => unsupported_reason, "packages" => list, "skipped" => skipped, "warnings" => [] }.compact
    Host.transaction do
      PackageRecorder.record!(host_id: host.id, credential_id: host.agent_credentials.active.pick(:id), report: AgentApi::PackageReport.new(payload))
    end
  end

  # An enrolled Debian 13 host with an inventory (os overrides it) and, unless packages is nil, a package report.
  def debian_host(packages: [ [ "openssl", "3.5.0-1", "openssl" ] ], os: nil, **attributes)
    host = enrolled_host(**attributes).first
    record_inventory(host, **(os ? { os: } : {}))
    report_packages(host, packages) if packages
    host
  end

  def import_advisories(*records, full: false, origin: "file", source: "test.zip", operator: nil)
    Advisories::Import.new(origin:, source:, full:, operator:).call(Advisories::Reader.new(osv_directory(*records)))
  end
end

# Withdrawal guard thresholds for a group (review of #129): withdrawal_guard: { share: 1.0, min_records: 0 } turns
# it off for specs about the absence sweep itself; the guard has its own specs.
RSpec.shared_context "withdrawal guard thresholds" do
  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:withdraw_share, :withdraw_min_records)
    guard = example.metadata[:withdrawal_guard]
    config.withdraw_share = guard.fetch(:share, saved[:withdraw_share])
    config.withdraw_min_records = guard.fetch(:min_records, saved[:withdraw_min_records])
    example.run
  ensure
    config.withdraw_share, config.withdraw_min_records = saved.values_at(:withdraw_share, :withdraw_min_records)
  end
end

RSpec.configure do |config|
  config.include_context "withdrawal guard thresholds", :withdrawal_guard
  config.include AdvisoryHelpers
  config.after { @osv_dirs&.each { |dir| FileUtils.rm_rf(dir) } }
end
