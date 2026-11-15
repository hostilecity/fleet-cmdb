require "rails_helper"
require "action_cable/subscription_adapter/solid_cable"

# /health's live_updates check (#194, review of #218): a stopped Solid Cable listener thread is reported.
RSpec.describe CableHealth do
  let(:adapter) { ActionCable::SubscriptionAdapter::SolidCable.new(ActionCable.server) }

  it "passes for another adapter, and before any page has subscribed" do
    expect(described_class.listening?).to be(true) # the test environment's adapter
    expect(described_class.listening?(adapter)).to be(true)
  end

  it "fails, and logs it, when the listener thread has ended" do
    listener = ActionCable::SubscriptionAdapter::SolidCable::Listener.allocate # the real class, without starting it
    stopped = Thread.new { nil }.tap(&:join)
    listener.instance_variable_set(:@thread, stopped)
    adapter.instance_variable_set(:@listener, listener)
    expect(captured_log { expect(described_class.listening?(adapter)).to be(false) }).to include("[health] Solid Cable's listener thread has stopped")

    listener.instance_variable_set(:@thread, Thread.current)
    expect(described_class.listening?(adapter)).to be(true)
  end

  it "passes, with a warning, when Solid Cable's listener no longer has the shape it reads" do
    adapter.instance_variable_set(:@listener, Object.new)
    expect(captured_log { expect(described_class.listening?(adapter)).to be(true) }).to include("cannot see Solid Cable's listener thread")
  end
end
