# A CIS-aligned rule (P2-S04, FR-2.2, DEC-12): its stable key, whether it is evaluated, and its current
# definition. Every change is audited with before and after values (FR-S.3). Imports (CisRules::Import) and
# the dashboard (P2-D06) both change rules through define!, enable!, and disable!, and every change
# re-evaluates the rule on every host once it commits (CisEvaluationJob, P2-S06).
class CisRule < ApplicationRecord
  has_many :versions, -> { order(:version) }, class_name: "CisRuleVersion", inverse_of: :cis_rule, dependent: :restrict_with_exception
  belongs_to :current_version, class_name: "CisRuleVersion", optional: true

  validates :key, format: { with: /\A[a-z0-9][a-z0-9-]{0,63}\z/ }

  scope :enabled, -> { where(enabled: true) }

  # Where a change was made, recorded as "source" in its audit entry (P2-D06): a rules file uploaded in the dashboard,
  # the dashboard's add and edit form (and its enable and disable buttons), or the rules:import task. An entry
  # written before sources were recorded has none.
  SOURCES = %w[file_upload dashboard rules_import].freeze

  # Every change to the rules (an import, or the dashboard's add, edit, enable, and disable) runs in one
  # transaction holding this lock, so they are serialised and an import preview can tell whether the rules
  # changed since it was made (P2-D06).
  WRITE_LOCK = "cis_rules:import"

  def self.with_write_lock
    transaction do
      connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{connection.quote(WRITE_LOCK)}))")
      yield
    end
  end

  # A digest of every rule's key, enabled flag, and current version: it changes whenever any rule is created,
  # edited, enabled, or disabled (versions are never changed in place), so an import preview made against one
  # state is never applied to another (P2-D06).
  def self.state_digest = Digest::SHA256.hexdigest(JSON.generate(order(:id).pluck(:id, :enabled, :current_version_id)))

  # Creates the rule, or a new version of it when the definition differs from its current one. Returns
  # :created, :versioned, or :unchanged. Must run inside a transaction. source: one of SOURCES, or nil.
  def self.define!(definition, actor:, enabled: true, source: nil)
    rule = lock.find_by(key: definition.key)
    return rule.revise!(definition, actor:, source:) if rule

    rule = create!(key: definition.key, enabled:)
    rule.update!(current_version: rule.versions.create!(version: 1, **version_attributes(definition)))
    Audit.record(actor:, action: Audit::Actions::RULE_CREATED, target: rule,
                 changes: definition.fields.transform_values { |value| [ nil, value ] }.merge("version" => [ nil, 1 ], "enabled" => [ nil, enabled ], **source_change(source)))
    CisEvaluationJob.after_rule_change(rule.id)
    :created
  end

  def self.version_attributes(definition) = definition.fields.symbolize_keys.merge(content_hash: definition.content_hash)

  # { "source" => source } for an audit entry, or nothing when no source is given.
  def self.source_change(source)
    return {} if source.nil?
    raise ArgumentError, "unknown rule change source #{source.inspect}" unless SOURCES.include?(source)

    { "source" => source }
  end

  def revise!(definition, actor:, source: nil)
    before = current_version
    return :unchanged if before.content_hash == definition.content_hash

    after = versions.create!(version: before.version + 1, **self.class.version_attributes(definition))
    update!(current_version: after)
    changes = definition.fields.filter_map { |name, value| [ name, [ before.public_send(name), value ] ] unless before.public_send(name) == value }.to_h
    Audit.record(actor:, action: Audit::Actions::RULE_EDITED, target: self, changes: changes.merge("version" => [ before.version, after.version ], **self.class.source_change(source)))
    CisEvaluationJob.after_rule_change(id)
    :versioned
  end

  # True when the flag changed. Must run inside a transaction.
  def enable!(actor:, source: nil) = set_enabled!(true, actor:, source:)

  def disable!(actor:, source: nil) = set_enabled!(false, actor:, source:)

  private

  def set_enabled!(value, actor:, source:)
    return false if enabled == value

    update!(enabled: value)
    Audit.record(actor:, action: value ? Audit::Actions::RULE_ENABLED : Audit::Actions::RULE_DISABLED, target: self, changes: { "enabled" => [ !value, value ], **self.class.source_change(source) })
    CisEvaluationJob.after_rule_change(id)
    true
  end
end
