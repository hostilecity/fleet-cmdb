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

  def import_advisories(*records, full: false, origin: "file", source: "test.zip", operator: nil)
    Advisories::Import.new(origin:, source:, full:, operator:).call(Advisories::Reader.new(osv_directory(*records)))
  end
end

RSpec.configure do |config|
  config.include AdvisoryHelpers
  config.after { @osv_dirs&.each { |dir| FileUtils.rm_rf(dir) } }
end
