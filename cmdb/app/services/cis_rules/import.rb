module CisRules
  # Imports a rule file (P2-S04): validated as a whole first, then written in one transaction, so an invalid file
  # writes nothing. An unchanged rule gets no new version; a changed one does. A rule the file does not list is
  # left as it is unless disable_missing is set. A rule's enabled flag changes only when the file states it.
  # Concurrent imports, and the dashboard's rule changes, are serialised (CisRule.with_write_lock). Every changed rule is re-evaluated on every host once the import
  # commits (CisRule, P2-S06).
  class Import
    Result = Data.define(:errors, :created, :versioned, :unchanged, :enabled, :disabled) do
      def ok? = errors.empty?

      def changed? = [ created, versioned, enabled, disabled ].any?(&:any?)
    end

    # The rules changed after the import was previewed (expected_state), so nothing was written.
    class Stale < StandardError; end

    # expected_state: a CisRule.state_digest taken when the file was previewed (the dashboard's import, P2-D06).
    # When given, the import writes nothing and raises Stale unless the rules are still in that state once the
    # lock is held, so what is applied is exactly what was previewed.
    # source: where the import was started (CisRule::SOURCES), recorded in each audit entry.
    def self.call(text, actor:, disable_missing: false, manifest: ConfigManifest.current, expected_state: nil, source: nil)
      file = RuleFile.parse(text, manifest:)
      return Result.new(errors: file.errors, created: [], versioned: [], unchanged: [], enabled: [], disabled: []) unless file.valid?

      new(file, actor:, disable_missing:, expected_state:, source:).call
    end

    def initialize(file, actor:, disable_missing:, expected_state: nil, source: nil)
      @file = file
      @actor = actor
      @disable_missing = disable_missing
      @expected_state = expected_state
      @source = source
      @outcomes = Hash.new { |hash, key| hash[key] = [] }
    end

    def call
      CisRule.with_write_lock do
        raise Stale, "the rules changed since the file was previewed" if @expected_state && CisRule.state_digest != @expected_state

        @file.rules.each { |rule| apply(rule) }
        disable_missing if @disable_missing
      end
      Result.new(errors: [], **%i[created versioned unchanged enabled disabled].to_h { |name| [ name, @outcomes[name] ] })
    end

    private

    def apply(rule)
      key = rule.definition.key
      @outcomes[CisRule.define!(rule.definition, actor: @actor, enabled: rule.enabled != false, source: @source)] << key
      return if rule.enabled.nil?

      stored = CisRule.find_by!(key:)
      if rule.enabled
        @outcomes[:enabled] << key if stored.enable!(actor: @actor, source: @source)
      elsif stored.disable!(actor: @actor, source: @source)
        @outcomes[:disabled] << key
      end
    end

    def disable_missing
      listed = @file.rules.map { |rule| rule.definition.key }
      CisRule.enabled.where.not(key: listed).order(:key).lock.each do |rule|
        @outcomes[:disabled] << rule.key if rule.disable!(actor: @actor, source: @source)
      end
    end
  end
end
