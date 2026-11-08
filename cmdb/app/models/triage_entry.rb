# A distribution tracker's triage of one CVE for one source package in one release (P2-S16, ADR 0022), as the
# last import that stored the release left it. An annotation beside a finding: nothing reads it to decide a
# finding's state, severity, or counts.
#
# - status: "open", "resolved", or "undetermined", as the tracker says.
# - urgency: "unimportant", "low", "medium", "high", or "end-of-life", or nil when none is assigned
#   ("not yet assigned", empty); urgency_raw keeps the tracker's text ("low*").
# - no_dsa: the security team plans no advisory for it; no_dsa_note is their note ("Minor issue") and
#   no_dsa_reason nil for a plain no-DSA, or "postponed" or "ignored".
# - next_point_update: a fix is planned for the release's next point release.
class TriageEntry < ApplicationRecord
  STATUSES = %w[open resolved undetermined].freeze
  URGENCIES = %w[unimportant low medium high end-of-life].freeze
end
