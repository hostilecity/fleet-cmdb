module Advisories
  # The severity rule (DEC-11, P2-S10): every advisory gets one of critical, high, medium, low, or unknown,
  # and keeps the raw value it came from. The first of these that the record has decides:
  #
  # 1. A CVSS v3 vector in the record's severity, then in an affected entry's: its base score, banded as CVSS
  #    bands it (9.0 and up critical, 7.0 high, 4.0 medium, below that low; a score of 0.0 is low too).
  # 2. database_specific.severity as a word (critical, high, moderate or medium, low), as GitHub's and some
  #    other databases publish it.
  # 3. A Debian urgency (ecosystem_specific.urgency of an affected entry, or database_specific.urgency):
  #    high, medium, and low or unimportant map to themselves and low. Debian has no critical.
  # 4. Otherwise unknown. A CVSS v2 or v4 vector is kept as the raw value but not scored.
  module Severity
    Result = Data.define(:level, :raw)

    WORDS = { "critical" => "critical", "high" => "high", "moderate" => "medium", "medium" => "medium", "low" => "low" }.freeze
    URGENCIES = { "high" => "high", "medium" => "medium", "low" => "low", "unimportant" => "low" }.freeze
    RAW_LIMIT = 512

    module_function

    # data: the parsed OSV record. affected: its affected entries for the fleet's ecosystems.
    def of(data, affected)
      vectors = cvss_entries(data["severity"]) + affected.flat_map { |entry| cvss_entries(entry["severity"]) }
      v3 = vectors.find { |_, vector| Cvss3.base_score(vector) }
      return Result.new(level: band(Cvss3.base_score(v3.last)), raw: clean(v3.last)) if v3

      word = text(data.dig("database_specific", "severity"))
      return Result.new(level: WORDS[word.downcase], raw: clean("database_specific.severity: #{word}")) if word && WORDS.key?(word.downcase)

      urgency = affected.filter_map { |entry| text(entry.dig("ecosystem_specific", "urgency")) }.first || text(data.dig("database_specific", "urgency"))
      if urgency
        level = URGENCIES[urgency.downcase.delete_suffix("*")] || "unknown" # the tracker marks an unconfirmed urgency with *
        return Result.new(level:, raw: clean("urgency: #{urgency}"))
      end

      Result.new(level: "unknown", raw: vectors.first && clean(vectors.first.last))
    end

    def band(score)
      if score >= 9.0 then "critical"
      elsif score >= 7.0 then "high"
      elsif score >= 4.0 then "medium"
      else "low"
      end
    end

    # [[type, vector], ...] from an OSV severity array.
    def cvss_entries(list)
      return [] unless list.is_a?(Array)

      list.filter_map { |entry| [ entry["type"], entry["score"] ] if entry.is_a?(Hash) && entry["score"].is_a?(String) }
    end

    def text(value) = value.is_a?(String) && value.present? ? value.strip : nil

    def clean(value) = Record.clean_text(value, RAW_LIMIT)
  end
end
