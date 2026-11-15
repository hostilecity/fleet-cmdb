require "rails_helper"

# The per-process cache of the settings sent to agents (#189).
RSpec.describe SettingsCache do
  it "keeps a value for TTL, then reads it again" do
    reads = 0
    2.times { expect(described_class.fetch(:example) { reads += 1 }).to eq(1) }
    expect(reads).to eq(1)
    later = described_class.clock + described_class::TTL.to_f + 1
    allow(described_class).to receive(:clock).and_return(later)
    expect(described_class.fetch(:example) { reads += 1 }).to eq(2)
  end

  it "is cleared when a setting change commits, not when it rolls back" do
    described_class.fetch(:example) { :old }
    Setting.transaction(requires_new: true) do
      Setting.create!(key: "agent.heartbeat_seconds", value: 120)
      raise ActiveRecord::Rollback
    end
    expect(described_class.fetch(:example) { :new }).to eq(:old)
    Setting.update_agent_intervals!(heartbeat_seconds: 120, actor: Audit::SYSTEM)
    expect(described_class.fetch(:example) { :new }).to eq(:new)
  end

  it "does not store a value that was read while a change committed" do
    value = described_class.fetch(:example) do
      described_class.clear # a change commits while this value is being read
      :read_before_the_change
    end
    expect(value).to eq(:read_before_the_change) # this caller still gets what it read
    expect(described_class.fetch(:example) { :after }).to eq(:after) # but the next one reads again
  end

  it "is safe to share between threads" do
    reads = Concurrent::AtomicFixnum.new
    values = Array.new(8) do
      Thread.new { Array.new(200) { described_class.fetch(:shared) { reads.increment && :value } } }
    end.flat_map(&:value)
    expect(values.uniq).to eq([ :value ])
    expect(reads.value).to be_between(1, 8) # at most one read per thread that found it empty
  end
end
