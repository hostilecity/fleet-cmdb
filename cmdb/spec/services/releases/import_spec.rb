require "rails_helper"

# P1-S15: a verified release is stored (binary on disk, manifest and signature in the database) and audited
# with the operator as actor; releases are immutable and never deleted while a host runs them.
RSpec.describe Releases::Import do
  let(:operator) { create(:operator) }

  before { trust_release_keys }

  def import(release, source: "upload", expected_version: nil, binary: release.binary)
    described_class.new(operator:, source:, expected_version:)
      .call(manifest: release.manifest, signature: release.signature) { StringIO.new(binary) }
  end

  # A statement the database refuses, in a savepoint so the example's transaction carries on.
  def refused_by_database(&) = ActiveRecord::Base.transaction(requires_new: true, &)

  def stored_files = Releases.store.dir.exist? ? Releases.store.dir.children.map { |path| path.basename.to_s } : []

  it "stores a verified release and audits the import with the operator as actor" do
    release = signed_release(version: "1.2.0")
    result = import(release)
    expect(result.created).to be(true)
    stored = result.release.reload
    expect(stored).to have_attributes(version: "1.2.0", target: Releases::TARGET, sha256: release.sha256, size: 4096,
                                      manifest: release.manifest, signature: release.signature, key_id: release_key.id_hex,
                                      key_role: "current", source: "upload", imported_by: operator,
                                      trusted_comment: "fleet-agent 1.2.0 #{Releases::TARGET} release manifest")
    expect(File.binread(stored.binary_path)).to eq(release.binary)
    expect(stored_files).to eq([ "fleet-agent-1.2.0-#{Releases::TARGET}" ]) # no staging file left behind
    entry = AuditEntry.last
    expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, action: "release.imported",
                                     target_type: "AgentRelease", target_id: stored.id)
    expect(entry.changeset).to eq("version" => "1.2.0", "sha256" => release.sha256, "size" => 4096,
                                  "key_id" => release_key.id_hex, "key_role" => "current", "source" => "upload")
  end

  it "records a release signed with the next key as such" do
    trust_release_keys(current: release_key, next_key: next_release_key)
    expect(import(signed_release(key: next_release_key)).release.key_role).to eq("next")
  end

  it "refuses a modified binary and stores nothing" do
    release = signed_release
    modified = release.binary.reverse
    expect { import(release, binary: modified) }.to raise_error(Releases::Refused, "the binary's SHA-256 does not match the manifest")
    expect { import(release, binary: release.binary + "x") }.to raise_error(Releases::Refused, /larger than the manifest's/)
    expect(AgentRelease.count).to eq(0)
    expect(AuditEntry.count).to eq(0) # the caller audits refusals (record_refusal)
    expect(stored_files).to eq([])
  end

  it "does not ask for the binary when the signature does not verify" do
    release = signed_release(key: TestReleaseKey.new)
    expect {
      described_class.new(operator:, source: "upload").call(manifest: release.manifest, signature: release.signature) { raise "binary read" }
    }.to raise_error(Releases::Refused, /does not trust/)
  end

  it "refuses a manifest for another version than the one asked for" do
    expect { import(signed_release(version: "1.2.0"), expected_version: "1.3.0") }
      .to raise_error(Releases::Refused, "the signed manifest is for version 1.2.0, not 1.3.0")
  end

  it "changes nothing when the same release is imported again, and refuses a different one for that version" do
    release = signed_release(version: "1.2.0")
    first = import(release).release
    again = import(release)
    expect(again).to have_attributes(release: first, created: false)
    expect(AuditEntry.where(action: "release.imported").count).to eq(1)
    expect { import(signed_release(version: "1.2.0")) }.to raise_error(Releases::Refused, "a different release 1.2.0 is already imported")
    expect(File.binread(first.binary_path)).to eq(release.binary)
  end

  it "resolves two imports of one version racing past the first check" do
    release = signed_release(version: "1.2.0")
    allow(AgentRelease).to receive(:find_by).and_call_original
    allow(AgentRelease).to receive(:find_by).with(version: "1.2.0").and_return(nil, nil)
    first = import(release).release # wins the lock
    allow(AgentRelease).to receive(:find_by).with(version: "1.2.0").and_return(nil, first)
    expect(import(release)).to have_attributes(release: first, created: false)
    expect(stored_files).to eq([ "fleet-agent-1.2.0-#{Releases::TARGET}" ])
  end

  it "audits refusals and failures with the operator as actor, in the caller's transaction" do
    import = AgentReleaseImport.create!(version: "1.2.0", operator:)
    described_class.record_refusal(operator:, source: "github", version: "1.2.0", reason: "the manifest signature is not valid") do
      import.finish!("refused", reason: "the manifest signature is not valid")
    end
    described_class.record_failure(operator:, source: "upload", version: nil, reason: "GitHub answered HTTP 500")
    refused, failed = AuditEntry.order(:id).last(2)
    expect(refused).to have_attributes(actor_type: "operator", actor_id: operator.id, action: "release.import_refused", target_id: nil,
                                       changeset: { "version" => "1.2.0", "source" => "github", "reason" => "the manifest signature is not valid" })
    expect(failed).to have_attributes(action: "release.import_failed", changeset: { "source" => "upload", "reason" => "GitHub answered HTTP 500" })
    expect(import.reload.state).to eq("refused")
  end

  it "removes the installed binary when the release's rows roll back after it was moved into place (review of #74)" do
    allow(Audit).to receive(:record).and_raise(ActiveRecord::StatementInvalid, "connection lost")
    expect { import(signed_release) }.to raise_error(ActiveRecord::StatementInvalid)
    expect(AgentRelease.count).to eq(0)
    expect(stored_files).to eq([])
  end

  it "removes the staging file when storing fails" do
    release = signed_release
    allow(Releases::Store).to receive(:new).and_wrap_original do |original, dir|
      original.call(dir).tap { |store| allow(store).to receive(:install).and_raise(Errno::ENOSPC) }
    end
    expect { import(release) }.to raise_error(Errno::ENOSPC)
    expect(stored_files).to eq([])
    expect(AgentRelease.count).to eq(0)
  end

  describe "AgentRelease" do
    let(:release) { import(signed_release(version: "1.2.0")).release }

    it "is never deleted while a host in the fleet runs it, by the model or the database" do
      host, = enrolled_host
      host.update_columns(agent_version: "1.2.0")
      expect { release.destroy }.to raise_error(AgentRelease::InUse)
      expect { refused_by_database { AgentRelease.where(id: release.id).delete_all } }.to raise_error(ActiveRecord::InvalidForeignKey, /in use by a host/)
      expect(AgentRelease.exists?(release.id)).to be(true)
    end

    it "may be deleted once no host in the fleet runs it" do
      host, = enrolled_host
      host.update_columns(agent_version: "1.2.0")
      host.retire!(actor: Audit::SYSTEM)
      expect(release.destroy).to be_destroyed
    end

    it "is immutable, and the table cannot be truncated" do
      release # imported outside the savepoints below
      expect { refused_by_database { AgentRelease.where(id: release.id).update_all(sha256: "0" * 64) } }.to raise_error(ActiveRecord::StatementInvalid, /immutable/)
      expect { refused_by_database { AgentRelease.where(id: release.id).update_all(manifest: "{}") } }.to raise_error(ActiveRecord::StatementInvalid, /immutable/)
      expect(release.update(updated_at: 1.minute.from_now)).to be(true) # bookkeeping columns may change
      expect { refused_by_database { ActiveRecord::Base.connection.execute("TRUNCATE agent_releases CASCADE") } }.to raise_error(ActiveRecord::StatementInvalid, /not truncated/)
    end

    it "orders by SemVer precedence and offers the newest stable release for install" do
      %w[1.10.0 1.9.0 2.0.0-rc.1 1.10.0-rc.2].each { |version| import(signed_release(version:)) }
      expect(AgentRelease.newest_first.map(&:version)).to eq(%w[2.0.0-rc.1 1.10.0 1.10.0-rc.2 1.9.0])
      expect(AgentRelease.current.version).to eq("1.10.0")
    end
  end
end
