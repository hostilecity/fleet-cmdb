# A release going out to the fleet in stages (P1-UPDATES, ADR 0018). Change one only through Rollouts, which
# audits every action. States: running, halted (a failure, rollback, or missing confirmation, or an
# operator, stopped it until an operator resumes it), completed, cancelled. At most one is open (running or
# halted) at a time; the database enforces it.
class Rollout < ApplicationRecord
  STATES = %w[running halted completed cancelled].freeze
  OPEN_STATES = %w[running halted].freeze

  belongs_to :agent_release
  belongs_to :started_by, class_name: "Operator"
  belongs_to :halted_by, class_name: "Operator", optional: true
  belongs_to :resumed_by, class_name: "Operator", optional: true
  has_many :rollout_hosts, dependent: :restrict_with_exception
  has_many :agent_updates, dependent: :restrict_with_exception

  validates :state, inclusion: { in: STATES }

  scope :open_now, -> { where(state: OPEN_STATES) }

  def self.current = open_now.first

  def final_stage? = current_stage == stage_percents.size
end
