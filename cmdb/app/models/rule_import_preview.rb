# A rules file an operator uploaded and is previewing (P2-D06, owner decision Q13), kept so "Apply import" applies
# exactly the file that was previewed: the same bytes (sha256), the same "disable rules this file does not list"
# choice, and only while the rules are as they were when it was previewed (rules_digest, CisRule.state_digest).
#
# - Short-lived: it expires TTL after the preview and is dropped when it is applied, cancelled, or replaced, and
#   RuleImportPreviewPruneJob deletes expired rows. An expired preview is never applied.
# - Bounded: one per operator (store! replaces the operator's earlier one), and only a file that passed every check
#   of the import, so at most CisRules::RuleFile::MAX_BYTES (a database check constraint holds the same limit).
# - Tied to the operator who uploaded it: for_operator only finds the operator's own, by a random token that names
#   it in the preview's URL and the apply form, so another tab's later upload is never applied in its place.
# - In the database, never on disk, so nothing is written under public/ or tmp/.
class RuleImportPreview < ApplicationRecord
  TTL = 15.minutes
  FILENAME_MAX = 255

  belongs_to :operator

  scope :live, ->(now = Time.current) { where("expires_at > ?", now) }

  # The operator's unexpired preview with this token, or nil.
  def self.for_operator(operator, token) = live.find_by(operator:, token: token.to_s)

  # Stores a checked file for the operator, replacing any earlier preview of theirs.
  def self.store!(operator:, filename:, body:, disable_missing:, rules_digest:, now: Time.current)
    transaction do
      # The operator's row, so two uploads at once are serialised even when there is no preview row yet to lock
      # (review of #130): the second waits, then replaces the first.
      Operator.lock.find(operator.id)
      where(operator:).delete_all
      create!(operator:, token: SecureRandom.urlsafe_base64(32), filename: display_filename(filename), body:, sha256: Digest::SHA256.hexdigest(body),
              disable_missing:, rules_digest:, expires_at: now + TTL)
    end
  end

  # The name the browser gave the file, as text that fits the column: valid UTF-8, no NUL (PostgreSQL cannot store
  # one), at most FILENAME_MAX characters. Shown escaped like any other text.
  def self.display_filename(name)
    name = name.to_s.dup.force_encoding(Encoding::UTF_8).scrub("?").delete("\0").strip.first(FILENAME_MAX)
    name.presence || "rules file"
  end

  def self.prune!(now = Time.current) = where(expires_at: ..now).delete_all

  # A new preview of the same file against the rules as they are now (after the rules changed in between), under a
  # new token, so a form from the earlier preview can no longer apply it (review of #130).
  def restart!(rules_digest:, now: Time.current) = update!(rules_digest:, expires_at: now + TTL, token: SecureRandom.urlsafe_base64(32))
end
