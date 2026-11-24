# An operator's decision on one host's finding for one advisory (VT-OVERRIDES #261, VT-S06, FR-2.6; epic decisions 12,
# 14, 15), covering every binary package the advisory matches on the host:
#
# - control: a compensating control is in place (rule O1). While it applies, the finding is in Low risk, scored as
#   "Low risk by a control"; a known exploited one keeps its "Known exploited" tier (VT-SCORES).
# - accepted: the risk is accepted until a date. It changes no bucket, points, or tier: the finding stays where the
#   rules put it (normally Needs attention), marked, and leaves "decisions due".
#
# Neither changes a finding's state or severity, or any open count. A decision applies through expires_on (UTC) and
# ends once (FindingDecisions): by an operator, at expiry, when a fix appears, when every finding it covers resolves,
# or suspended when the evidence gets worse than recorded (evidence). Ended is final and nothing is ever deleted
# (finding_decisions_guard); every change is audited.
class FindingDecision < ApplicationRecord
  KINDS = %w[control accepted].freeze
  ENDINGS = %w[operator expired fixed suspended resolved].freeze
  KIND_NAMES = { "control" => "Control in place", "accepted" => "Risk accepted" }.freeze
  REASON_LENGTH = 10..1000

  belongs_to :host
  belongs_to :advisory
  belongs_to :created_by, class_name: "Operator"
  belongs_to :ended_by, class_name: "Operator", optional: true

  scope :active, -> { where(ended_at: nil) }
  # Active and not past its last day: what the triage and the tab treat as in force.
  scope :in_force, ->(today = Date.current) { active.where(expires_on: today..) }

  validates :kind, inclusion: { in: KINDS }
  validates :reason, length: { in: REASON_LENGTH }

  # Operator text made safe to keep and show (VT-S06, "sanitised"): invalid UTF-8 dropped, control and format
  # characters (bidi overrides, zero-width spaces) and line breaks made spaces, and runs of spaces squeezed. Views
  # still escape it everywhere it is shown, including the audit log.
  def self.sanitize_reason(text) = text.to_s.dup.force_encoding(Encoding::UTF_8).scrub("").gsub(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/, " ").squish

  def control? = kind == "control"
  def accepted? = kind == "accepted"
  def active? = ended_at.nil?
  def suspended? = ended_why == "suspended"

  # In force on a day: active and not past its last day.
  def in_force?(today = Date.current) = active? && expires_on >= today

  # Active, but past its last day: FindingDecisionExpiryJob has not ended it yet.
  def lapsed?(today = Date.current) = active? && expires_on < today

  def kind_name = KIND_NAMES.fetch(kind)
end
