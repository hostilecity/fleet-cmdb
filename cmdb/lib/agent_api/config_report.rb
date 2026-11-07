module AgentApi
  # Turns a schema-valid config report (docs/api config.request) into the facts to store, checking each value
  # against the fact manifest (P2-S02, FR-2.1, DEC-08). Failures raise ValidationFailed with a JSON Pointer per
  # problem, before anything is written.
  #
  # - A manifest version newer than the server's is refused: the agent read a manifest this server never
  #   published, so its facts cannot be checked. An older version is fine.
  # - A fact key the manifest does not have is ignored (ignored_keys, logged by the controller), as DEC-08 does
  #   for unknown fields: a newer agent may know a fact this server has not been told about yet.
  # - A value of the wrong type or past the manifest's limits is refused, as is a NUL anywhere in a value, which
  #   PostgreSQL cannot store.
  # - Every manifest fact the report leaves out is recorded as missing, with a reason, so no fact is silently
  #   absent: a fact added after the report's manifest version says so.
  #
  # facts is { key => { "state" => "ok" | "unreadable" | "unsupported" | "missing", "value" => ..., "reason" => ... } }
  # for every fact in the current manifest, sorted by key, with unordered lists sorted (ConfigManifest::Fact#normalize):
  # the form the rule evaluator reads (CisRules::Evaluator).
  class ConfigReport
    STATES = %w[ok unreadable unsupported missing].freeze
    OBJECT_FIELDS = { "file_attributes" => %w[mode owner group], "service_state" => %w[active enabled] }.freeze
    MAX_IGNORED = 100

    attr_reader :report_id, :schema_version, :collected_at, :manifest_version, :facts, :ignored_keys

    def initialize(payload, manifest: ConfigManifest.current)
      @report_id = payload["report_id"]
      @schema_version = payload["schema_version"]
      @collected_at = Time.iso8601(payload["collected_at"])
      @manifest_version = payload["manifest_version"]
      problems = []
      if manifest_version > manifest.version
        problems << { "pointer" => "/manifest_version", "problem" => "is newer than this server's fact manifest (version #{manifest.version}); fetch GET /api/v1/manifest/config again" }
        raise ValidationFailed.new(details: problems)
      end

      reported = payload["facts"]
      @ignored_keys = reported.keys.reject { |key| manifest.key?(key) }.sort
      @facts = manifest.facts.to_h { |fact| [ fact.key, entry(fact, reported[fact.key], problems) ] }
      raise ValidationFailed.new(details: problems.first(64)) if problems.any?

      @facts.freeze
    end

    # SHA-256 of the facts as stored: the same facts hash the same whatever order the agent sent them in, and a
    # change of state or reason is a change too.
    def content_hash = OpenSSL::Digest::SHA256.hexdigest(JSON.generate(facts))

    # How many facts are in each state, for display: { "ok" => 80, "unreadable" => 2, ... }.
    def counts = STATES.index_with { |state| facts.count { |_, fact| fact["state"] == state } }

    private

    def entry(fact, sent, problems)
      return missing(fact) if sent.nil?

      pointer = "/facts/#{fact.key.gsub('~', '~0').gsub('/', '~1')}"
      state = sent["state"]
      unless state == "ok"
        reason = sent["reason"].gsub(InventoryReport::CONTROL_CHARACTERS, "").presence || "The agent gave no readable reason."
        return { "state" => state, "value" => nil, "reason" => reason }
      end

      value = shape(fact, sent["value"])
      errors = fact.value_errors(value)
      errors << "contains a NUL character" if errors.empty? && nul?(value)
      problems.concat(errors.map { |error| { "pointer" => "#{pointer}/value", "problem" => "#{error} (#{fact.key} is #{fact.type})" } })
      { "state" => "ok", "value" => errors.empty? ? fact.normalize(value) : value, "reason" => nil } # an invalid list may not sort
    end

    def missing(fact)
      reason = if fact.since > manifest_version
        "Added in manifest version #{fact.since}; the agent reported against version #{manifest_version}."
      else
        "The agent's report did not include this fact."
      end
      { "state" => "missing", "value" => nil, "reason" => reason }
    end

    # A file's or unit's fields in a fixed order, without any field the schema does not declare (DEC-08).
    def shape(fact, value)
      fields = OBJECT_FIELDS[fact.type]
      fields && value.is_a?(Hash) ? fields.to_h { |field| [ field, value[field] ] } : value
    end

    def nul?(value)
      case value
      when String then value.include?("\0")
      when Array then value.any? { |item| nul?(item) }
      when Hash then value.values.any? { |item| nul?(item) }
      else false
      end
    end
  end
end
