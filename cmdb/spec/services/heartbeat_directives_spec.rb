require "rails_helper"

# The heartbeat's directives in one statement (#189).
RSpec.describe HeartbeatDirectives do
  it "reads the rollout offer with the columns Rollouts builds its directive from, in the same order" do
    expect(described_class::OFFER_JSON).to eq("json_build_array(#{Rollouts::OFFER_COLUMNS.join(', ')})")
  end
end
