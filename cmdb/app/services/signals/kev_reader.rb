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
  #
  # Bounded before parsing (review of #269): 16 MiB of "{}" would otherwise parse into 5.6 million Hashes (1.1 GB). A
  # scan of the bytes, outside strings, refuses more than MAX_CONTAINERS objects and arrays in all, more than MAX_ENTRIES
  # values two levels deep (entries of any type), or an entry larger than MAX_ENTRY_BYTES, so JSON.parse only ever sees a catalog-shaped document. After
  # parsing, a catalog with no valid entry, or whose valid entries fall short of its own count by more than
  # FLEET_ADVISORY_WITHDRAW_SHARE, is refused too: it is a broken file, not a smaller catalog.
  class KevReader
    Catalog = Data.define(:version, :count, :entries, :malformed, :repeated, :problems)
    Entry = Data.define(:cve_id, :date_added, :due_date, :known_ransomware, :vendor, :product)

    TEXT_LIMIT = 128
    MAX_ENTRIES = 50_000 # the catalog had 1,786 in November 2026
    MAX_ENTRY_BYTES = 64.kilobytes # an entry is about 1 KB
    MAX_CONTAINERS = 4 * MAX_ENTRIES # each entry is an object and its cwes array
    STRUCTURE = /["{}\[\],]/n
    STRING_END = /["\\]/n
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

      bytes = @path.binread
      check_shape(bytes)
      data = parse(bytes)
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
      raise unreadable("has no valid entry (#{@malformed} malformed)") if kept.empty?
      if count && kept.size < count * (1 - Advisories.config.withdraw_share)
        raise unreadable("has #{kept.size} valid entries of the #{count} its count gives (#{@malformed} malformed)")
      end
      Catalog.new(version:, count:, entries: kept, malformed: @malformed, repeated: entries.size - kept.size, problems: @problems)
    end

    private

    # Counts, outside strings, the objects and arrays in all and the values two levels deep (the catalog's entries, of
    # any type: a comma at that depth starts another one), and sizes the entries, without building anything; raises
    # Unreadable past a limit, or at a string the file ends inside. So "[1,1,1,...]" or "["","",...]" is refused here
    # as quickly as "[{},{},...]" (re-review of #269).
    def check_shape(bytes)
      scanner = StringScanner.new(bytes)
      depth = containers = values = 0
      entry_start = nil
      while scanner.skip_until(STRUCTURE)
        byte = bytes.getbyte(scanner.pos - 1)
        case byte
        when 0x22 # a string: to its closing quote, over escapes
          skip_string(scanner, bytes)
        when 0x2C # ,
          values = count_value(values) if depth == 2
        when 0x7B, 0x5B # { [
          containers += 1
          raise unreadable("has more than #{MAX_CONTAINERS.to_fs(:delimited)} objects and arrays") if containers > MAX_CONTAINERS

          values = count_value(values) if depth == 1 # the first value of a top-level list (one too many when it is empty)
          entry_start = scanner.pos if depth == 2 && byte == 0x7B
          depth += 1
        else # } ]
          depth -= 1
          if depth == 2 && entry_start
            raise unreadable("has an entry larger than #{MAX_ENTRY_BYTES / 1.kilobyte} KiB") if scanner.pos - entry_start > MAX_ENTRY_BYTES

            entry_start = nil
          end
        end
      end
    end

    def count_value(values)
      raise unreadable("has more than #{MAX_ENTRIES.to_fs(:delimited)} entries") if values + 1 > MAX_ENTRIES

      values + 1
    end

    # From just past an opening quote to just past its closing one, stepping over escapes.
    def skip_string(scanner, bytes)
      loop do
        raise unreadable("is not valid JSON") unless scanner.skip_until(STRING_END)
        break if bytes.getbyte(scanner.pos - 1) == 0x22
        raise unreadable("is not valid JSON") if scanner.eos? # a backslash as the last byte

        scanner.pos += 1
      end
    end

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
