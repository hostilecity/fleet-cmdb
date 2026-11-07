# What a host's last config report said (P2-S02, FR-2.1): every manifest fact with its state, value, and reason
# (AgentApi::ConfigReport), how many facts are in each state, the report's manifest version, and the fact keys
# it sent that the manifest does not have. The facts as they were whenever they changed are ConfigSnapshots.
class HostConfig < ApplicationRecord
  belongs_to :host

  # The facts that could not be read, with the agent's reason (AC-2.5): { key => reason }.
  def unreadable = facts.filter_map { |key, fact| [ key, fact["reason"] ] if fact["state"] == "unreadable" }.to_h
end
