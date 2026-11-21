# The daily re-triage (VT-BUCKETS #259, VT-S05): EPSS band changes and Debian tracker changes are coalesced into one
# run a day, after the daily EPSS import (config/recurring.yml), so they cost one pass a day. It starts the run whatever
# the EPSS import did: tracker changes need it too. KEV changes start their own run at once (Signals::KevImport).
class TriageDailyJob < ApplicationJob
  queue_as :default

  def perform
    return nil unless TriageSignalChange.exists?

    EvaluationRun.start!("triage", { "reason" => "daily" })
  end
end
