module CisRules
  # What importing a rule file would do, worked out without writing anything (P2-D06, rules-import-preview.html):
  # the rules it would add, the rules that would get a new version (with each field before and after), the
  # enabled flags it would change, the rules it lists unchanged, and the stored rules it does not list (disabled
  # when disable_missing is set, as Import does). The file is checked by RuleFile.parse, the import's own checks,
  # so a file that plans cleanly imports as planned unless the rules change in between; state_digest is
  # CisRule.state_digest at the time of the plan, for Import's expected_state.
  #
  # Reads only. Outside a transaction it reads in one REPEATABLE READ, READ ONLY transaction (as CisDryRun), so the
  # plan and its digest describe one committed state of the rules.
  module ImportPlan
    Result = Data.define(:errors, :plan) do
      def ok? = errors.empty?
    end

    Added = Data.define(:definition, :enabled)
    # changes: { field => [before, after] }, in DEFINITION_FIELDS order.
    Changed = Data.define(:key, :from_version, :to_version, :changes)
    Flag = Data.define(:key, :from, :to)
    # disable: whether applying disables it (disable_missing and the rule is enabled).
    NotListed = Data.define(:key, :enabled, :disable)

    Plan = Data.define(:rule_count, :added, :changed, :flags, :unchanged, :not_listed, :disable_missing, :total_after, :state_digest) do
      def enabling = flags.select(&:to)

      def disabling = flags.reject(&:to) + not_listed.select(&:disable)

      # Whether applying would write anything at all.
      def changes? = [ added, changed, flags ].any?(&:any?) || not_listed.any?(&:disable)
    end

    module_function

    def call(text, disable_missing: false, manifest: ConfigManifest.current)
      file = RuleFile.parse(text, manifest:)
      return Result.new(errors: file.problems, plan: nil) unless file.valid?

      Result.new(errors: [], plan: read_only { plan(file.rules, disable_missing) })
    end

    def plan(rules, disable_missing)
      stored = CisRule.includes(:current_version).order(:key).to_a.index_by(&:key)
      out = { added: [], changed: [], flags: [], unchanged: [] }
      rules.each do |rule|
        definition = rule.definition
        existing = stored[definition.key]
        next out[:added] << Added.new(definition:, enabled: rule.enabled != false) unless existing

        version = existing.current_version
        changed = version.content_hash != definition.content_hash
        out[:changed] << Changed.new(key: definition.key, from_version: version.version, to_version: version.version + 1, changes: field_changes(version, definition)) if changed
        flag = !rule.enabled.nil? && rule.enabled != existing.enabled
        out[:flags] << Flag.new(key: definition.key, from: existing.enabled, to: rule.enabled) if flag
        out[:unchanged] << definition.key unless changed || flag
      end
      listed = rules.to_set { |rule| rule.definition.key }
      not_listed = stored.values.reject { |rule| listed.include?(rule.key) }.map { |rule| NotListed.new(key: rule.key, enabled: rule.enabled, disable: disable_missing && rule.enabled) }
      Plan.new(rule_count: rules.size, **out, not_listed:, disable_missing:, total_after: stored.size + out[:added].size, state_digest: CisRule.state_digest)
    end

    def field_changes(version, definition)
      before = version.attributes.slice(*DEFINITION_FIELDS)
      after = definition.fields
      DEFINITION_FIELDS.filter_map { |name| [ name, [ before[name], after[name] ] ] unless before[name] == after[name] }.to_h
    end

    # Inside a caller's transaction the reads join it; otherwise they share one read-only snapshot of the database.
    def read_only(&)
      connection = ActiveRecord::Base.connection
      return yield if connection.transaction_open?

      ActiveRecord::Base.transaction(isolation: :repeatable_read) do
        connection.execute("SET TRANSACTION READ ONLY")
        yield
      end
    end

    private_class_method :plan, :field_changes, :read_only
  end
end
