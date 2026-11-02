require "rails_helper"

RSpec.describe Releases::StoreCheck do
  before { trust_release_keys }

  it "is healthy with no releases" do
    expect(described_class.problems).to eq([])
    expect(described_class).to be_healthy
  end

  it "is healthy when the newest release's binary is present with the recorded size" do
    import_release(signed_release(version: "1.0.0"))
    import_release(signed_release(version: "1.1.0"))

    expect(described_class).to be_healthy
  end

  it "names the newest release when its binary is missing or the wrong size" do
    older = import_release(signed_release(version: "1.0.0"))
    newest = import_release(signed_release(version: "1.1.0"))

    File.write(newest.binary_path, "short")
    expect(described_class.problems).to eq([ "1.1.0" ])

    File.delete(newest.binary_path)
    expect(described_class.problems).to eq([ "1.1.0" ])

    # Only the newest release is checked: an older one's file is not what every update depends on.
    File.delete(older.binary_path)
    expect(described_class.problems).to eq([ "1.1.0" ])
  end

  it "does not look at an older release's file" do
    older = import_release(signed_release(version: "1.0.0"))
    import_release(signed_release(version: "1.1.0"))
    File.delete(older.binary_path)

    expect(described_class).to be_healthy
  end

  describe "a rollout's target (P1-UPDATES)" do
    let!(:target) { import_release(signed_release(version: "1.0.0")) }
    let!(:newest) { import_release(signed_release(version: "1.1.0")) }
    let(:canary) { host_running("0.1.0").first }

    it "is checked while the rollout is running, even when a newer release exists" do
      rollout = start_rollout(release: target, canaries: [ canary ])
      File.delete(target.binary_path)

      expect(rollout.state).to eq("running")
      expect(described_class.problems).to eq([ "1.0.0" ])
    end

    it "is not checked once the rollout is halted, completed, or cancelled" do
      rollout = start_rollout(release: target, canaries: [ canary ])
      File.delete(target.binary_path)

      rollout.update_columns(state: "halted")
      expect(described_class).to be_healthy
      rollout.update_columns(state: "cancelled", open_slot: nil)
      expect(described_class).to be_healthy
    end

    it "is listed once when it is also the newest release, and with the newest when both are missing" do
      rollout = start_rollout(release: newest, canaries: [ canary ])
      File.delete(newest.binary_path)
      expect(described_class.problems).to eq([ "1.1.0" ])

      rollout.update_columns(state: "halted")
      File.delete(target.binary_path)
      rollout.update_columns(state: "running", agent_release_id: target.id)
      expect(described_class.problems).to contain_exactly("1.0.0", "1.1.0")
    end
  end
end
