require "rails_helper"

RSpec.describe Enrollment::IssueToken do
  let(:host) { create(:host) }

  it "returns a token once, stores only its digest, and audits the issue" do
    token = described_class.call(host:, actor: Audit::SYSTEM)
    record = host.enrollment_tokens.sole
    expect(record.token_digest).to eq(AgentApi.digest(token))
    expect(EnrollmentToken.where(token_digest: token)).to be_empty
    expect(record.expires_at).to be_within(1.minute).of(24.hours.from_now)
    entry = AuditEntry.for_target(host).chronological.last
    expect(entry.action).to eq(Audit::Actions::HOST_ENROLLMENT_TOKEN_ISSUED)
    expect(entry.changeset.to_json).not_to include(token)
  end

  it "expires earlier unredeemed tokens" do
    first = described_class.call(host:, actor: Audit::SYSTEM)
    described_class.call(host:, actor: Audit::SYSTEM)
    expect(EnrollmentToken.find_by(token_digest: AgentApi.digest(first))).not_to be_redeemable
    expect(host.enrollment_tokens.redeemable.count).to eq(1)
  end

  it "starts re-enrollment for active and revoked hosts and leaves pending hosts pending" do
    expect { described_class.call(host:, actor: Audit::SYSTEM) }.not_to(change { host.reload.enrollment_state })
    active = create(:host, :active)
    described_class.call(host: active, actor: Audit::SYSTEM)
    expect(active.reload.enrollment_state).to eq("pending")
    revoked = create(:host, :revoked)
    described_class.call(host: revoked, actor: Audit::SYSTEM)
    expect(revoked.reload.enrollment_state).to eq("pending")
  end

  it "refuses retired hosts" do
    expect { described_class.call(host: create(:host, :retired), actor: Audit::SYSTEM) }.to raise_error(described_class::HostRetired)
  end

  it "uses the configured lifetime" do
    described_class.call(host:, actor: Audit::SYSTEM, ttl: 2.hours)
    expect(host.enrollment_tokens.sole.expires_at).to be_within(1.minute).of(2.hours.from_now)
  end
end

RSpec.describe "Credential revocation through host transitions (FR-1.1, AC-1.5)" do
  it "revokes the active credential when the host is revoked or retired, and audits its key id" do
    %i[revoke! retire!].each do |transition|
      host, credential = enrolled_host
      key_id = credential.split(".").first
      host.public_send(transition, actor: Audit::SYSTEM)
      expect(AgentCredential.authenticate("Bearer #{credential}")).to be_nil
      expect(host.agent_credentials.sole).to have_attributes(state: "revoked", revoked_at: be_present)
      expect(AuditEntry.for_target(host).chronological.last.changeset).to include("revoked_key_id" => key_id)
    end
  end

  it "stores only a digest of the secret and keeps it out of inspect" do
    host, credential = enrolled_host
    record = host.agent_credentials.sole
    expect(record.secret_digest).to eq(AgentApi.digest(credential.split(".").last))
    expect(record.inspect).not_to include(record.secret_digest)
    issued = AgentCredential.issue!(host: create(:host))
    expect(issued.inspect).not_to include(issued.plaintext.split(".").last)
  end

  it "allows only one active credential per host" do
    host, = enrolled_host
    expect { AgentCredential.issue!(host:) }.to raise_error(ActiveRecord::RecordNotUnique)
  end
end
