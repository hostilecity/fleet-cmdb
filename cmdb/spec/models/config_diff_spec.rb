require "rails_helper"

# Comparing two sets of config facts (P2-S02, FR-2.1, AC-2.1).
RSpec.describe ConfigDiff do
  def ok(value) = { "state" => "ok", "value" => value, "reason" => nil }
  def unreadable(reason) = { "state" => "unreadable", "value" => nil, "reason" => reason }

  let(:before) { { "sshd.permitrootlogin" => ok("no"), "file:/etc/shadow" => ok({ "mode" => "0640", "owner" => "root", "group" => "shadow" }), "users.login" => ok(%w[root]) } }

  it "finds a changed value, and a change of state alone (ok to unreadable)" do
    after = before.merge("sshd.permitrootlogin" => ok("yes"), "file:/etc/shadow" => unreadable("Permission denied"))
    diff = described_class.between(before, after)
    expect(diff.changed.map(&:key)).to eq([ "file:/etc/shadow", "sshd.permitrootlogin" ])
    shadow, root_login = diff.changed
    expect(shadow).to have_attributes(state_changed?: true, from: before["file:/etc/shadow"], to: unreadable("Permission denied"))
    expect(root_login).to have_attributes(state_changed?: false, value_changed?: true)
    expect([ diff.added, diff.removed ]).to eq([ {}, {} ])
  end

  it "finds a new reason for an unreadable fact as a change, with no value change" do
    diff = described_class.between({ "file:/etc/shadow" => unreadable("busy") }, { "file:/etc/shadow" => unreadable("denied") })
    expect(diff.changed.first).to have_attributes(state_changed?: false, value_changed?: false)
  end

  it "finds facts added and removed, as when the manifest changed" do
    after = before.except("users.login").merge("sshd.banner" => ok("/etc/issue.net"))
    diff = described_class.between(before, after)
    expect(diff.added).to eq("sshd.banner" => ok("/etc/issue.net"))
    expect(diff.removed).to eq("users.login" => ok(%w[root]))
    expect(diff.changed).to eq([])
  end

  it "is empty for the same facts, and adds everything for a first snapshot" do
    expect(described_class.between(before, before.to_a.reverse.to_h)).to be_empty
    expect(described_class.between(nil, before).added.keys).to eq(before.keys.sort)
  end

  it "compares a host's snapshot with the one before it" do
    host = create(:host)
    at = Time.current
    snapshots = [ before, before.merge("sshd.permitrootlogin" => ok("yes")) ].each_with_index.map do |facts, i|
      ConfigSnapshot.create!(host:, facts:, content_hash: SecureRandom.hex(32), manifest_version: 1, report_id: SecureRandom.uuid, collected_at: at, received_at: at + i)
    end
    expect(described_class.for(snapshots.last).changed.map(&:key)).to eq([ "sshd.permitrootlogin" ])
    expect(described_class.for(snapshots.first).added.size).to eq(3)
  end
end
