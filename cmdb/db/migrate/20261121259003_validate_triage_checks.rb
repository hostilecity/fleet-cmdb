# Validates the two triage checks 20261121259001 added NOT VALID (review of #277): before the triage run fills them,
# every existing row has bucket, bucket_rule, and kev (or base_*) all NULL, which passes, so this only proves it and
# makes the checks hold for every row. VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE, so reports and matching keep
# writing while it scans; but it reads the whole table, so at container start it runs only on tables of at most
# VulnerabilityTriage::Checks::INLINE_BYTES of heap (seconds with a warm cache, up to about a minute cold). A larger one is left NOT VALID (new rows are
# checked all the same), and bin/rails vulnerabilities:validate_triage_checks validates it while the server runs
# (docs/operations/upgrades.md).
class ValidateTriageChecks < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    VulnerabilityTriage::Checks.validate!(inline: true).each { |line| say(line, true) }
  end

  def down
    # Nothing to undo: 20261121259001's down drops the checks.
  end
end
