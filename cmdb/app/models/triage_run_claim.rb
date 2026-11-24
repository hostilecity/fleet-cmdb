# A triage_signal_changes row a triage run claimed (#295, EvaluationRun::Triage): stored as the run claims, so a resume
# re-triages from what it claimed and releases only that. Deleted once released, and with its run.
class TriageRunClaim < ApplicationRecord
  self.primary_key = %i[evaluation_run_id triage_signal_change_id]
end
