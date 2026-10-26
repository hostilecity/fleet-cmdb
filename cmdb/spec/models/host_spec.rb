require "rails_helper"

RSpec.describe Host do
  let(:actor) { Audit::SYSTEM }

  def host_in(state)
    create(:host, *([ state.to_sym ] unless state == "pending"))
  end

  describe "FR-1.1 enrollment state machine" do
    it "starts new hosts as pending" do
      expect(Host.register!({ name: "VM 1", hostname: "vm-1.example.lan" }, actor:)).to have_attributes(enrollment_state: "pending")
    end

    it "refuses to create a host in any other state" do
      expect { create(:host, enrollment_state: "active") }.to raise_error(Host::InvalidTransition)
    end

    # Every row of the FR-1.1 table. (none) -> pending is creation, covered above.
    allowed = {
      [ "pending", :activate ] => "active",          # agent redeems the enrollment token
      [ "active", :revoke ] => "revoked",            # operator revokes the credential
      [ "revoked", :begin_reenrollment ] => "pending", # operator issues a new token
      [ "active", :begin_reenrollment ] => "pending",  # operator issues a new token; old credential still works
      [ "pending", :retire ] => "retired",           # any -> retired
      [ "active", :retire ] => "retired",
      [ "revoked", :retire ] => "retired"
    }

    allowed.each do |(from, event), to|
      it "allows #{from} -> #{to} by #{event}" do
        host = host_in(from)
        host.public_send(:"#{event}!", actor:)
        expect(host.reload.enrollment_state).to eq(to)
      end
    end

    rejected = Host::ENROLLMENT_STATES.product(Host::TRANSITIONS.keys) - allowed.keys
    rejected.each do |from, event|
      it "rejects #{event} from #{from}" do
        host = host_in(from)
        expect { host.public_send(:"#{event}!", actor:) }.to raise_error(Host::InvalidTransition)
        expect(host.reload.enrollment_state).to eq(from)
      end
    end

    it "covers every state and event in the rejection list" do
      expect(rejected.map(&:first).uniq).to match_array(Host::ENROLLMENT_STATES)
      expect(rejected).to include([ "retired", :retire ], [ "retired", :activate ], [ "pending", :revoke ])
    end

    it "treats retired as terminal" do
      host = host_in("retired")
      Host::TRANSITIONS.each_key { |event| expect(host.can_transition?(event)).to be(false) }
    end

    it "raises when enrollment_state is changed without a transition" do
      host = host_in("pending")
      expect { host.update!(enrollment_state: "active") }.to raise_error(Host::InvalidTransition)
      expect { host.update(enrollment_state: "active") }.to raise_error(Host::InvalidTransition)
      expect(host.reload.enrollment_state).to eq("pending")
    end

    it "audits each transition with the before and after state" do
      host = host_in("pending")
      host.activate!(actor:)
      entry = AuditEntry.for_target(host).chronological.last
      expect(entry).to have_attributes(action: Audit::Actions::HOST_ENROLLED, actor_type: "system",
                                       changeset: { "enrollment_state" => %w[pending active] })
    end

    it "leaves the state unchanged when the audit entry cannot be written" do
      host = host_in("active")
      allow(Audit).to receive(:record).and_raise(Audit::Error)
      expect { host.revoke!(actor:) }.to raise_error(Audit::Error)
      expect(host.reload.enrollment_state).to eq("active")
    end
  end

  describe "no hard delete" do
    it "refuses destroy and delete" do
      host = host_in("retired")
      expect { host.destroy }.to raise_error(Host::HardDeleteNotAllowed)
      expect { host.delete }.to raise_error(Host::HardDeleteNotAllowed)
      expect(Host.exists?(host.id)).to be(true)
    end
  end

  describe "scopes" do
    let!(:pending) { host_in("pending") }
    let!(:active) { host_in("active") }
    let!(:revoked) { host_in("revoked") }
    let!(:retired) { host_in("retired") }

    it "excludes retired hosts from the fleet" do
      expect(Host.in_fleet).to contain_exactly(pending, active, revoked)
    end

    it "selects active hosts" do
      expect(Host.active).to contain_exactly(active)
    end

    it "applies liveness to active hosts only" do
      Host.where(id: [ active.id, revoked.id ]).update_all(liveness_status: "online")
      expect(Host.with_liveness("online")).to contain_exactly(active)
    end

    it "filters by tag, normalising the query" do
      tagged = create(:host, tags: %w[web lab])
      create(:host, tags: %w[media])
      expect(Host.tagged(" Web ")).to contain_exactly(tagged)
      expect(Host.in_fleet.tagged("lab")).to contain_exactly(tagged)
    end

    it "uses the GIN index for tag filters" do
      expect(Host.tagged("web").to_sql).to include("@>")
    end
  end

  describe "tags" do
    it "normalises case, whitespace, blanks, and duplicates" do
      host = build(:host, tags: [ " Web ", "web", "Home Lab", "", "MEDIA" ])
      expect(host.tags).to eq(%w[web home-lab media])
    end

    it "accepts a comma-separated string" do
      expect(build(:host, tags: "web, lab ,web").tags).to eq(%w[web lab])
    end

    it "limits the number of tags" do
      host = build(:host, tags: (1..Host::MAX_TAGS + 1).map { |i| "t#{i}" })
      expect(host).not_to be_valid
      expect(host.errors[:tags].join).to include("at most #{Host::MAX_TAGS}")
    end

    it "limits length and characters" do
      expect(build(:host, tags: [ "a" * 32 ])).to be_valid
      expect(build(:host, tags: [ "a" * 33 ])).not_to be_valid
      expect(build(:host, tags: [ "web<script>" ])).not_to be_valid
      expect(build(:host, tags: [ "-web" ])).not_to be_valid
    end
  end

  describe "validation of operator-editable fields" do
    it "normalises the hostname and name" do
      host = build(:host, hostname: " VM-01.Example.LAN. ", name: "  Media   server ")
      expect(host).to have_attributes(hostname: "vm-01.example.lan", name: "Media server")
    end

    it "rejects invalid hostnames" do
      [ "", "-vm.example.lan", "vm_01.example.lan", "vm..example.lan", "#{'a' * 64}.example.lan", "vm 01" ].each do |hostname|
        expect(build(:host, hostname:)).not_to be_valid, "expected #{hostname.inspect} to be rejected"
      end
    end

    it "limits lengths" do
      expect(build(:host, name: "a" * 101)).not_to be_valid
      expect(build(:host, description: "a" * 1_001)).not_to be_valid
      expect(build(:host, notes: "a" * 10_001)).not_to be_valid
      expect(build(:host, name: "a" * 100, description: "a" * 1_000, notes: "a" * 10_000)).to be_valid
    end

    it "rejects control characters, allowing line breaks in free text" do
      expect(build(:host, name: "vm\u0007")).not_to be_valid
      expect(build(:host, description: "line one\u001b[31m")).not_to be_valid
      expect(build(:host, notes: "line one\nline two\ttabbed")).to be_valid
    end
  end

  describe ".register! and #edit!" do
    it "audits creation with the initial values" do
      host = Host.register!({ name: "VM 1", hostname: "vm-1.example.lan", tags: [ "web" ], enrollment_state: "active" }, actor:)
      expect(host.enrollment_state).to eq("pending")
      entry = AuditEntry.for_target(host).sole
      expect(entry.action).to eq(Audit::Actions::HOST_CREATED)
      expect(entry.changeset).to include("hostname" => [ nil, "vm-1.example.lan" ], "tags" => [ nil, [ "web" ] ],
                                         "enrollment_state" => [ nil, "pending" ])
    end

    it "audits edits with before and after values, ignoring non-editable attributes" do
      host = host_in("active")
      host.edit!({ notes: "Runs the media stack", tags: "media", enrollment_state: "retired", liveness_status: "online" }, actor:)
      expect(host.reload).to have_attributes(notes: "Runs the media stack", tags: [ "media" ], enrollment_state: "active",
                                             liveness_status: nil)
      entry = AuditEntry.for_target(host).chronological.last
      expect(entry.action).to eq(Audit::Actions::HOST_EDITED)
      expect(entry.changeset).to eq("notes" => [ nil, "Runs the media stack" ], "tags" => [ [], [ "media" ] ])
    end

    it "writes nothing for a no-op edit" do
      host = host_in("pending")
      expect { host.edit!({ name: host.name }, actor:) }.not_to change(AuditEntry, :count)
    end

    it "writes nothing when the edit is invalid" do
      host = host_in("pending")
      expect { host.edit!({ hostname: "not a hostname" }, actor:) }.to raise_error(ActiveRecord::RecordInvalid)
      expect(AuditEntry.for_target(host).pluck(:action)).to eq([ Audit::Actions::HOST_CREATED ])
    end
  end
end
