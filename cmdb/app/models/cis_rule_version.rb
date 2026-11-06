# One definition of a CIS-aligned rule (P2-S04, FR-2.2). Never changed once written: an edit is a new version,
# and results name the version that produced them (P2-S06), so old versions stay readable and history is
# never rewritten.
class CisRuleVersion < ApplicationRecord
  belongs_to :cis_rule

  def readonly? = persisted? || super

  # delete skips readonly?, so it is refused here too (review of #101).
  def delete = raise(ActiveRecord::ReadOnlyRecord, "rule versions cannot be deleted")

  def definition = CisRules::Definition.new(key: cis_rule.key, **CisRules::DEFINITION_FIELDS.to_h { |name| [ name.to_sym, public_send(name) ] })
end
