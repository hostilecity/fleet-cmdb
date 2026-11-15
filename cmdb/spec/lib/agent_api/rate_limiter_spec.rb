require "rails_helper"

# The agent API's in-memory rate-limit counters (#191).
RSpec.describe AgentApi::RateLimiter do
  subject(:limiter) { described_class.new(max_keys: 100) }

  let(:now) { [ 1_000.0 ] }

  before { allow(limiter).to receive(:clock) { now.first } }

  def later(seconds) = now[0] += seconds

  it "counts per key within the window" do
    expect(Array.new(3) { limiter.increment("a", 1, expires_in: 60) }).to eq([ 1, 2, 3 ])
    expect(limiter.increment("b", 1, expires_in: 60)).to eq(1)
    expect(limiter.count("a")).to eq(3)
    expect(limiter.count("unknown")).to eq(0)
  end

  it "starts a new window once the old one has ended, from the first count after it" do
    2.times { limiter.increment("a", 1, expires_in: 60) }
    later(59.9)
    expect(limiter.increment("a", 1, expires_in: 60)).to eq(3) # still the first window
    later(0.1)
    expect(limiter.count("a")).to eq(0)
    expect(limiter.increment("a", 1, expires_in: 60)).to eq(1)
    later(59.9)
    expect(limiter.count("a")).to eq(1)
  end

  it "holds at most max_keys counters however many keys arrive, dropping the least recently counted" do
    limiter.increment("runaway", 1, expires_in: 60)
    1_000.times do |i|
      limiter.increment("key-#{i}", 1, expires_in: 60)
      limiter.increment("runaway", 1, expires_in: 60) # counted often, so never the least recently counted
    end
    expect(limiter.size).to eq(100)
    expect(limiter.count("runaway")).to eq(1_001)
    expect(limiter.count("key-0")).to eq(0) # dropped: its count starts again
    expect(limiter.count("key-999")).to eq(1)
  end

  it "drops ended windows as new counts arrive, so memory follows the active keys" do
    50.times { |i| limiter.increment("old-#{i}", 1, expires_in: 60) }
    later(61)
    limiter.increment("new", 1, expires_in: 60)
    expect(limiter.size).to eq(1)
  end

  it "keeps a key checked with touch: true from being dropped first (review of #211)" do
    limiter.increment("blocked", 60, expires_in: 60)
    1_000.times do |i|
      limiter.increment("other-#{i}", 1, expires_in: 60)
      limiter.count("blocked", touch: true) # the blocked address tries again
    end
    expect(limiter.count("blocked")).to eq(60)
  end

  it "drops a key read without touch first, as before" do
    limiter.increment("quiet", 60, expires_in: 60)
    100.times { |i| limiter.increment("other-#{i}", 1, expires_in: 60) }
    expect(limiter.count("quiet")).to eq(0)
  end

  it "remembers a key with a sliding expiry" do
    limiter.remember("fa_key", expires_in: 900)
    later(899)
    expect(limiter.live?("fa_key")).to be(true)
    limiter.remember("fa_key", expires_in: 900) # seen again: 900 s from now
    later(899)
    expect(limiter.live?("fa_key")).to be(true)
    later(1)
    expect(limiter.live?("fa_key")).to be(false)
    expect(limiter.live?("never")).to be(false)
  end

  # A Hash that hands the thread over in the middle of increment's read-modify-write (after the window is taken out,
  # before it is put back). Without the mutex, another thread then finds no window and starts a new count, so counts
  # are lost; with it, the other thread waits. Plain threads would not show this: under the GVL these few hash
  # operations do not interleave by themselves (review of #211).
  class SwitchingHash < Hash
    def delete(key)
      super.tap { Thread.pass }
    end
  end

  it "loses no count when threads switch inside the critical section" do
    shared = described_class.new(max_keys: 500)
    shared.instance_variable_set(:@windows, SwitchingHash.new)
    Array.new(8) { Thread.new { 200.times { shared.increment("shared", 1, expires_in: 60) } } }.each(&:join)
    expect(shared.count("shared")).to eq(1_600)
  end

  it "stays bounded when threads share it" do
    shared = described_class.new(max_keys: 500)
    Array.new(8) { |t| Thread.new { 1_000.times { |i| shared.increment("thread-#{t}-#{i}", 1, expires_in: 60) } } }.each(&:join)
    expect(shared.size).to be <= 500
  end

  it "clears every counter" do
    limiter.increment("a", 1, expires_in: 60)
    limiter.clear
    expect(limiter.size).to eq(0)
  end
end
