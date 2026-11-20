# Helpers for the exploitation signal specs (VT-SIGNALS, #257). spec/fixtures/signals holds recorded files in the
# formats the sources publish: CISA's KEV catalog JSON (as CISA's GitHub mirror serves it) and FIRST's EPSS gzip CSV.
# Their CVE ids, vendors, and scores are invented and name no real vulnerability.
module SignalHelpers
  SIGNAL_FIXTURES = Rails.root.join("spec/fixtures/signals")

  # One KEV catalog entry in CISA's shape.
  def kev_vulnerability(cve_id, date_added: "2026-11-02", due_date: "2026-11-23", ransomware: "Unknown", **extra)
    { "cveID" => cve_id, "vendorProject" => "Example Vendor", "product" => "Example Product", "vulnerabilityName" => "Example",
      "dateAdded" => date_added, "shortDescription" => "Invented.", "requiredAction" => "Apply updates.", "dueDate" => due_date,
      "knownRansomwareCampaignUse" => ransomware, "notes" => "", "cwes" => [] }.merge(extra.transform_keys(&:to_s))
  end

  # A KEV catalog file of the given entries (Hashes, or CVE ids made into entries), or of raw text.
  def kev_file(*entries, version: "2026.11.19", raw: nil)
    document = raw || JSON.generate("title" => "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion" => version,
                                    "dateReleased" => "2026-11-19T15:00:00.000Z", "count" => entries.size,
                                    "vulnerabilities" => entries.map { |e| e.is_a?(String) ? kev_vulnerability(e) : e })
    signal_tempfile("known_exploited_vulnerabilities.json", document)
  end

  # An EPSS file: rows is [[cve, score, percentile], ...] or raw lines; gzip unless gzip: false.
  def epss_file(rows, date: "2026-11-19", version: "v2025.03.14", gzip: true, preamble: nil)
    lines = preamble || [ "#model_version:#{version},score_date:#{date}T12:55:00Z", "cve,epss,percentile" ]
    text = (lines + rows.map { |row| row.is_a?(Array) ? row.join(",") : row }).join("\n") + "\n"
    signal_tempfile(gzip ? "epss_scores-current.csv.gz" : "epss_scores-current.csv", gzip ? ActiveSupport::Gzip.compress(text) : text)
  end

  def signal_tempfile(name, content)
    dir = Pathname(Dir.mktmpdir("signals-"))
    @signal_dirs = [ *@signal_dirs, dir ]
    dir.join(name).tap { |path| path.binwrite(content) }
  end

  def import_kev(path, origin: "file", source: "kev.json", **)
    Signals::KevImport.new(origin:, source:, **).call(Signals::KevReader.new(path).read)
  end

  def import_epss(path, origin: "file", source: "epss.csv.gz", **)
    Signals::EpssImport.new(origin:, source:, **).call(Signals::EpssReader.new(path))
  end

  # A stored advisory naming the CVEs: DEBIAN-<first CVE> with the others as aliases.
  def advisory_for(*cve_ids, severity: "high", severity_raw: nil, **)
    Advisory.create!(advisory_id: "DEBIAN-#{cve_ids.first}", source: "test", aliases: cve_ids.drop(1), severity:, severity_raw:, modified_at: Time.current, **)
  end

  # An open finding of the advisory on a new host.
  def open_finding_for(advisory, host: enrolled_host.first, state: "open")
    VulnerabilityFinding.create!(host:, advisory:, package: "openssl", architecture: "amd64", state:, first_seen_at: Time.current,
                                 resolution: (state == "resolved" ? "fixed" : nil), resolved_at: (Time.current if state == "resolved"))
  end

  def pending_changes(kind) = TriageSignalChange.where(kind:).order(:cve_id, :advisory_id).pluck(Arel.sql("coalesce(cve_id, advisory_id::text, kind)"))
end

RSpec::Matchers.define_negated_matcher :not_include, :include unless RSpec::Matchers.method_defined?(:not_include)

RSpec.configure do |config|
  config.include SignalHelpers
  config.after { @signal_dirs&.each { |dir| FileUtils.rm_rf(dir) } }
end
