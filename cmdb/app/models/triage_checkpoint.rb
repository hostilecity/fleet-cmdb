# Where a triage job stopped (TriageListenerExpiryJob), kept in the database so a cache eviction or a restore of the
# cache does not lose it (fourth review of #277). One row per name.
class TriageCheckpoint < ApplicationRecord
  self.primary_key = :name

  def self.at(name) = find_by(name:)&.at

  # Moves it forward only, so two overlapping runs cannot move it back (the later write would otherwise win).
  def self.move!(name, at) = upsert({ name:, at: }, unique_by: :name, on_duplicate: Arel.sql("at = GREATEST(triage_checkpoints.at, EXCLUDED.at)"))

  # Sets it whatever it was: for a checkpoint found ahead of the clock.
  def self.reset!(name, at) = upsert({ name:, at: }, unique_by: :name)
end
