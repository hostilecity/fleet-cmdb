module Signals
  # Reads CISA's Known Exploited Vulnerabilities catalog (VT-S02), the JSON document CISA publishes and its GitHub
  # mirror copies: { "catalogVersion": "2026.11.19", "count": 1771, "vulnerabilities": [ { "cveID", "vendorProject",
  # "product", "dateAdded", "dueDate", "knownRansomwareCampaignUse", ... } ] }.
  #
  # The file is at most max_bytes (FLEET_KEV_MAX_DOWNLOAD_MB, 16 MiB; the catalog is 1 to 2 MB), so it is parsed whole.
  # Only the CVE id, date added, due date, known ransomware use, vendor, and product are kept; vendor and product are
  # cleaned text capped at TEXT_LIMIT. An entry that is not in that shape is skipped and counted as malformed (the first
  # PROBLEM_LIMIT with why); a CVE listed twice keeps its first entry. A file that is not the catalog at all (not JSON,
  # no vulnerabilities list, no entry, too large) raises Advisories::Unreadable, and nothing is imported.
  class KevReader
    Catalog = Data.define(:version, :count, :entries, :malformed, :repeated, :problems)
    Entry = Data.define(:cve_id, :date_added, :due_date, :known_ransomware, :vendor, :product)

    TEXT_LIMIT = 128
    PROBLEM_LIMIT = 100
    DATE = /\A\d{4}-\d\d-\d\d\z/
    VERSION = /\A[0-9A-Za-z][0-9A-Za-z._-]{0,63}\z/

    def initialize(path, name: nil, max_bytes: Signals.config.kev_max_download_bytes)
      @path = Pathname(path)
      @name = Advisories::Record.clean_text(name || @path.basename.to_s, 200) || "file"
      @max_bytes = max_bytes
    end

    def read
      raise unreadable("is not a file") unless @path.file?
      raise unreadable("is larger than #{@max_bytes / 1.megabyte} MiB") if @path.size > @max_bytes

      data = parse(@path.binread)
      list = data["vulnerabilities"] if data.is_a?(Hash)
      raise unreadable("is not a KEV catalog (no vulnerabilities list)") unless list.is_a?(Array)
      raise unreadable("lists no vulnerabilities") if list.empty?

      @problems = []
      @malformed = 0
      seen = Set.new
      entries = list.each_with_index.filter_map { |item, index| entry(item, index) }
      kept = entries.select { |e| seen.add?(e.cve_id) }
      version = data["catalogVersion"].is_a?(String) && data["catalogVersion"].match?(VERSION) ? data["catalogVersion"] : nil
      count = data["count"].is_a?(Integer) ? data["count"] : nil
      Catalog.new(version:, count:, entries: kept, malformed: @malformed, repeated: entries.size - kept.size, problems: @problems)
    end

    private

    def parse(bytes)
      text = bytes.force_encoding(Encoding::UTF_8)
      raise unreadable("is not valid UTF-8") unless text.valid_encoding?

      JSON.parse(text, max_nesting: 8)
    rescue JSON::ParserError, JSON::NestingError
      raise unreadable("is not valid JSON")
    end

    def entry(item, index)
      raise ArgumentError, "is not an object" unless item.is_a?(Hash)

      cve_id = item["cveID"]
      raise ArgumentError, "has no valid cveID" unless cve_id.is_a?(String) && cve_id.match?(CVE)

      Entry.new(cve_id:, date_added: date(item["dateAdded"], "dateAdded", required: true), due_date: date(item["dueDate"], "dueDate"),
                known_ransomware: item["knownRansomwareCampaignUse"].to_s.strip.casecmp?("known"),
                vendor: Advisories::Record.clean_text(item["vendorProject"], TEXT_LIMIT), product: Advisories::Record.clean_text(item["product"], TEXT_LIMIT))
    rescue ArgumentError => e
      @malformed += 1
      id = item["cveID"] if item.is_a?(Hash) && item["cveID"].is_a?(String) && item["cveID"].match?(CVE)
      @problems << { "index" => index, "id" => id, "problem" => e.message }.compact if @problems.size < PROBLEM_LIMIT
      nil
    end

    def date(value, field, required: false)
      return nil if value.nil? && !required
      raise ArgumentError, "has no valid #{field}" unless value.is_a?(String) && value.match?(DATE)

      Date.iso8601(value)
    rescue Date::Error
      raise ArgumentError, "has no valid #{field}"
    end

    def unreadable(problem) = Advisories::Unreadable.new("#{@name} #{problem}, so nothing was imported")
  end
end
