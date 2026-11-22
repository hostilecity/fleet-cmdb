# Where a triage job stopped (TriageListenerExpiryJob), kept in the database so a cache eviction or a restore of the
# cache does not lose it (fourth review of #277). One row per name.
class TriageCheckpoint < ApplicationRecord
  self.primary_key = :name

  def self.at(name) = find_by(name:)&.at

  def self.move!(name, at) = upsert({ name:, at: }, unique_by: :name)
end
