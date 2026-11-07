module CisRules
  # Imports a rule file (P2-S04): validated as a whole first, then written in one transaction, so an invalid file
  # writes nothing. An unchanged rule gets no new version; a changed one does. A rule the file does not list is
  # left as it is unless disable_missing is set. A rule's enabled flag changes only when the file states it.
  # Concurrent imports are serialised. Every changed rule is re-evaluated on every host once the import
  # commits (CisRule, P2-S06).
  class Import
    Result = Data.define(:errors, :created, :versioned, :unchanged, :enabled, :disabled) do
      def ok? = errors.empty?

      def changed? = [ created, versioned, enabled, disabled ].any?(&:any?)
    end

    LOCK = "cis_rules:import"

    def self.call(text, actor:, disable_missing: false, manifest: ConfigManifest.current)
      file = RuleFile.parse(text, manifest:)
      return Result.new(errors: file.errors, created: [], versioned: [], unchanged: [], enabled: [], disabled: []) unless file.valid?

      new(file, actor:, disable_missing:).call
    end

    def initialize(file, actor:, disable_missing:)
      @file = file
      @actor = actor
      @disable_missing = disable_missing
      @outcomes = Hash.new { |hash, key| hash[key] = [] }
    end

    def call
      CisRule.transaction do
        CisRule.connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{CisRule.connection.quote(LOCK)}))")
        @file.rules.each { |rule| apply(rule) }
        disable_missing if @disable_missing
      end
      Result.new(errors: [], **%i[created versioned unchanged enabled disabled].to_h { |name| [ name, @outcomes[name] ] })
    end

    private

    def apply(rule)
      key = rule.definition.key
      @outcomes[CisRule.define!(rule.definition, actor: @actor, enabled: rule.enabled != false)] << key
      return if rule.enabled.nil?

      stored = CisRule.find_by!(key:)
      if rule.enabled
        @outcomes[:enabled] << key if stored.enable!(actor: @actor)
      elsif stored.disable!(actor: @actor)
        @outcomes[:disabled] << key
      end
    end

    def disable_missing
      listed = @file.rules.map { |rule| rule.definition.key }
      CisRule.enabled.where.not(key: listed).order(:key).lock.each do |rule|
        @outcomes[:disabled] << rule.key if rule.disable!(actor: @actor)
      end
    end
  end
end
