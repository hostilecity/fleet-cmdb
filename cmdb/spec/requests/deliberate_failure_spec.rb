require "rails_helper"

# Temporary: proves CI fails on a failing spec (P0-SERVER-CI acceptance). Reverted in the next commit.
RSpec.describe "Deliberate CI failure" do
  it "fails on purpose" do
    expect(1).to eq(2)
  end
end
