module Advisories
  # One OSV record (https://ossf.github.io/osv-schema/), validated and cleaned for storage (P2-S10, DEC-11,
  # NFR-1). Only the fleet profile's ecosystems are kept (Ecosystems); affected entries for others are ignored.
  #
  # A record is malformed, and Record.parse raises Malformed, when the fields this server uses are missing or
  # wrong: the id, modified, published and withdrawn times, and, for the fleet's ecosystems, package names and
  # ECOSYSTEM ranges. Everything kept is text with control characters removed and a length cap. A reference
  # is stored only when it is an http or https URL; others are counted as rejected and dropped.
  class Record
    class Malformed < StandardError; end

    Package = Data.define(:ecosystem, :package, :ranges, :fixed_version)

    ID = /\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z/
    # Debian source package names, as dpkg allows them (lower case).
    PACKAGE = /\A[a-z0-9][a-z0-9+._-]{0,127}\z/
    # A version as published: printable ASCII, no spaces. Whether dpkg can parse it is matching's question
    # (an unparseable bound leaves the package not evaluated, P2-S11), not a reason to refuse the record.
    VERSION = /\A[!-~]{1,256}\z/
    EVENTS = %w[introduced fixed last_affected limit].freeze
    REFERENCE_ORDER = %w[ADVISORY WEB REPORT ARTICLE].freeze
    SUMMARY_LIMIT = 512
    URL_LIMIT = 2048
    ALIAS_LIMIT = 32
    CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/

    attr_reader :advisory_id, :summary, :aliases, :severity, :severity_raw, :reference_url, :rejected_urls,
                :published_at, :modified_at, :withdrawn_at, :packages

    # Parses the bytes of one JSON document.
    def self.parse(bytes)
      text = bytes.dup.force_encoding(Encoding::UTF_8)
      raise Malformed, "is not valid UTF-8" unless text.valid_encoding?

      data = JSON.parse(text)
      raise Malformed, "is not a JSON object" unless data.is_a?(Hash)

      new(data)
    rescue JSON::ParserError
      raise Malformed, "is not valid JSON"
    end

    # Control characters removed, white space squashed, at most limit characters; nil when nothing is left.
    def self.clean_text(value, limit)
      return nil unless value.is_a?(String)

      value.gsub(CONTROL_CHARACTERS, " ").squish.truncate(limit, omission: "…").presence
    end

    # The id from a parsed document, if it has a valid one, for reporting a malformed record.
    def self.id_of(data) = data.is_a?(Hash) && data["id"].is_a?(String) && data["id"].match?(ID) ? data["id"] : nil

    def initialize(data)
      @advisory_id = data["id"]
      raise Malformed, "has no valid id" unless @advisory_id.is_a?(String) && @advisory_id.match?(ID)

      @modified_at = time(data, "modified", required: true)
      @published_at = time(data, "published")
      @withdrawn_at = time(data, "withdrawn")
      affected = fleet_affected(data["affected"])
      @packages = build_packages(affected)
      @summary = self.class.clean_text(data["summary"], SUMMARY_LIMIT) || self.class.clean_text(data["details"].to_s.lines.first, SUMMARY_LIMIT)
      @aliases = (list(data["aliases"]) + list(data["upstream"])).grep(ID).uniq.first(ALIAS_LIMIT)
      severity = Severity.of(data, affected)
      @severity = severity.level
      @severity_raw = severity.raw
      @reference_url, @rejected_urls = pick_reference(data["references"])
    end

    def withdrawn? = !withdrawn_at.nil?

    # The (ecosystem, package) pairs this record names.
    def package_keys = packages.map { |p| [ p.ecosystem, p.package ] }

    private

    def time(data, field, required: false)
      value = data[field]
      return nil if value.nil? && !required
      raise Malformed, "has no #{field} time" if value.nil?
      raise Malformed, "has a #{field} time that is not RFC 3339" unless value.is_a?(String) && value.match?(/\A\d{4}-\d\d-\d\dT/)

      Time.iso8601(value)
    rescue ArgumentError
      raise Malformed, "has a #{field} time that is not RFC 3339"
    end

    def fleet_affected(affected)
      return [] if affected.nil?
      raise Malformed, "has an affected list that is not an array" unless affected.is_a?(Array)

      affected.each_with_index.filter_map do |entry, i|
        raise Malformed, "has affected[#{i}] that is not an object" unless entry.is_a?(Hash)

        ecosystem = entry.dig("package", "ecosystem") if entry["package"].is_a?(Hash)
        entry.merge("index" => i) if Ecosystems.supported?(ecosystem)
      end
    end

    # One Package per ecosystem and source package, with the ranges of every affected entry naming it.
    def build_packages(affected)
      grouped = affected.group_by do |entry|
        name = entry["package"]["name"]
        raise Malformed, "has affected[#{entry['index']}] with an invalid package name" unless name.is_a?(String) && name.match?(PACKAGE)

        [ entry["package"]["ecosystem"], name ]
      end
      grouped.map do |(ecosystem, package), entries|
        ranges = entries.flat_map { |entry| ranges_of(entry) }
        fixed = ranges.flatten.filter_map { |event| event["fixed"] }.first
        Package.new(ecosystem:, package:, ranges:, fixed_version: fixed)
      end
    end

    # The ECOSYSTEM ranges' events, each as [{"introduced" => "0"}, {"fixed" => "1.2-3"}]. SEMVER and GIT ranges
    # do not use the package manager's versions and are ignored.
    def ranges_of(entry)
      at = "affected[#{entry['index']}]"
      ranges = entry["ranges"] || []
      raise Malformed, "has #{at}.ranges that is not an array" unless ranges.is_a?(Array)

      ranges.each_with_index.filter_map do |range, r|
        raise Malformed, "has #{at}.ranges[#{r}] that is not an object" unless range.is_a?(Hash)
        next unless range["type"] == "ECOSYSTEM"

        events = range["events"]
        raise Malformed, "has #{at}.ranges[#{r}] without events" unless events.is_a?(Array) && events.any?

        events = events.map do |event|
          kind, version = event.is_a?(Hash) && event.size == 1 ? event.first : nil
          raise Malformed, "has #{at}.ranges[#{r}] with an invalid event" unless EVENTS.include?(kind) && version.is_a?(String) && version.match?(VERSION)

          { kind => version }
        end
        raise Malformed, "has #{at}.ranges[#{r}] without an introduced event" if events.none? { |e| e.key?("introduced") }

        events
      end
    end

    def list(value) = value.is_a?(Array) ? value.grep(String) : []

    # The best http or https reference (an advisory first, then a web page, then any), and how many references
    # were dropped for another scheme or for not being a usable URL.
    def pick_reference(references)
      references = references.is_a?(Array) ? references.select { |r| r.is_a?(Hash) && r.key?("url") } : []
      valid, rejected = references.partition { |r| web_url?(r["url"]) }
      best = valid.min_by.with_index { |r, i| [ REFERENCE_ORDER.index(r["type"]) || REFERENCE_ORDER.size, i ] }
      [ best && best["url"], rejected.size ]
    end

    def web_url?(url)
      return false unless url.is_a?(String) && url.length <= URL_LIMIT && !url.match?(/[\s\u0000-\u001f\u007f-\u009f]/)

      uri = URI.parse(url)
      %w[http https].include?(uri.scheme&.downcase) && uri.host.present?
    rescue URI::InvalidURIError
      false
    end
  end
end
