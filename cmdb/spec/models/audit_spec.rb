require "rails_helper"

RSpec.describe Audit do
  let!(:host) { create(:host) }

  def record(**options)
    Audit.record(actor: Audit::SYSTEM, action: Audit::Actions::HOST_EDITED, target: host, **options)
  end

  describe ".record" do
    it "writes actor, action, target, changes, request id, and a server-side time" do
      Current.set(request_id: "req-1") do
        entry = record(changes: { "notes" => [ nil, "hello" ] })
        expect(entry.reload).to have_attributes(actor_type: "system", actor_id: nil, action: "host.edited",
                                                target_type: "Host", target_id: host.id, request_id: "req-1",
                                                changeset: { "notes" => [ nil, "hello" ] })
        expect(entry.occurred_at).to be_within(1.minute).of(Time.current)
      end
    end

    it "stores request ids up to the 255 characters ActionDispatch::RequestId accepts" do
      long_id = "r" * 255
      Current.set(request_id: long_id) { expect(record.reload.request_id).to eq(long_id) }
    end

    it "records a host as the actor" do
      entry = Audit.record(actor: host, action: Audit::Actions::HOST_ENROLLED, target: host)
      expect(entry).to have_attributes(actor_type: "host", actor_id: host.id)
    end

    it "rejects actors that are not Audit::SYSTEM or an auditable record" do
      expect { Audit.record(actor: "someone", action: Audit::Actions::HOST_EDITED) }.to raise_error(ArgumentError)
      expect { Audit.record(actor: build(:host), action: Audit::Actions::HOST_EDITED) }.to raise_error(ArgumentError)
    end

    it "rejects unknown actions" do
      expect { record(action: "host.renamed") }.to raise_error(Audit::UnknownAction)
    end

    it "must run inside a transaction" do
      allow(AuditEntry.connection).to receive(:transaction_open?).and_return(false)
      expect { record }.to raise_error(Audit::NotInTransaction)
    end

    it "defines every action in one place" do
      expect(Audit::Actions::ALL).to include("host.created", "host.edited", "host.enrolled", "host.credential_revoked",
                                             "host.retired", "host.enrollment_token_issued")
      expect(Audit::Actions::ALL).to eq(Audit::Actions::ALL.uniq)
    end
  end

  describe "transactions (FR-S.3)" do
    it "leaves no entry when the transaction that made the change fails" do
      expect do
        Host.transaction do
          host.update!(notes: "changed")
          record(changes: { "notes" => [ nil, "changed" ] })
          raise ActiveRecord::Rollback
        end
      end.not_to change(AuditEntry, :count)
      expect(host.reload.notes).to be_nil
    end

    it "leaves no change when the entry cannot be written" do
      expect do
        host.edit!({ notes: "changed" }, actor: build(:host)) # unsaved actor: Audit.record raises
      end.to raise_error(ArgumentError)
      expect(host.reload.notes).to be_nil
    end

    it "always has an entry for a committed change" do
      expect { host.retire!(actor: Audit::SYSTEM) }.to change { AuditEntry.for_target(host).count }.by(1)
    end
  end

  describe "secret scrubbing (NFR-1)" do
    it "raises outside production when a change names a secret" do
      expect(Audit.secret_mode).to eq(:raise)
      %w[enrollment_token credential secret_digest password authorization api_key].each do |key|
        expect { record(changes: { key => [ nil, "x" ] }) }.to raise_error(Audit::SecretInChangeset), key
      end
    end

    it "matches camelCase and hyphenated spellings" do
      %w[apiKey privateKey api-key accessKey APIKEY clientSecret refreshToken].each do |key|
        expect { record(changes: { key => [ nil, "x" ] }) }.to raise_error(Audit::SecretInChangeset), key
      end
    end

    it "raises for secrets nested anywhere in the changes" do
      expect { record(changes: { "details" => { "items" => [ { "token" => "x" } ] } }) }.to raise_error(Audit::SecretInChangeset)
    end

    it "filters instead of raising in production" do
      allow(Rails.env).to receive(:production?).and_return(true)
      entry = record(changes: { "hostname" => [ "a", "b" ], "details" => { "Credential" => "x", "privateKey" => "z" },
                                "token" => "y", "apiKey" => "w" })
      expect(entry.changeset).to eq("hostname" => %w[a b], "details" => { "Credential" => "[FILTERED]", "privateKey" => "[FILTERED]" },
                                    "token" => "[FILTERED]", "apiKey" => "[FILTERED]")
    end

    it "leaves ordinary fields alone" do
      changes = { "name" => %w[a b], "hostname" => %w[a b], "enrollment_state" => %w[pending active], "tags" => [ [], [ "web" ] ] }
      expect(record(changes:).changeset).to eq(changes)
    end
  end
end
