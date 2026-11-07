require "rails_helper"

# Uploaded advisory files imported in the background (P2-D06, owner decision on #129): the queued import is
# finished by the job, audited with the operator who uploaded it; the stored file is deleted however the import
# ends; a failure after the retries fails the import with a reason and the job, so it shows on the failed-jobs
# page; and AdvisoryUploadPruneJob deletes files whose job never ran or was interrupted.
RSpec.describe AdvisoryUploadImportJob, type: :job do
  include ActiveJob::TestHelper

  let(:operator) { create(:operator) }

  # A queued import and its stored file, as DataSourcesController#upload writes them.
  def queued_upload(bytes, filename: "upload.zip", full: false, at: Time.current)
    import = AdvisoryImport.create!(origin: "file", source: filename, full:, operator:, state: "queued", started_at: at)
    AdvisoryUpload.create!(advisory_import: import, operator:, filename:, byte_size: bytes.bytesize, data: bytes, created_at: at, expires_at: at + AdvisoryUpload::LIFETIME)
    import
  end

  def zip_bytes(entries) = osv_zip(entries).binread

  # Runs the job and its retries. The test helper wraps the error the last attempt raises; unwrap it.
  def run(import)
    perform_enqueued_jobs { described_class.perform_later(import.id) }
  rescue Minitest::UnexpectedError => e
    raise e.error
  end

  it "imports the stored file into its queued import, audited with the operator, stores the re-matching summary, and deletes the file" do
    debian_host(packages: [ [ "openssl", "3.5.0-1", "openssl" ] ])
    import = queued_upload(zip_bytes("DSA-9001-1.json" => osv_record(id: "DSA-9001-1"), "bad.json" => "{"))
    run(import)

    expect(import.reload).to have_attributes(state: "succeeded", operator:, ecosystems: [ "Debian:13" ], matching: { "packages" => 1, "hosts" => 1 })
    expect(import.finished_at).to be_present
    expect(import.counts).to include("records" => 2, "created" => 1, "malformed" => 1)
    expect(import.problems.sole).to include("location" => "bad.json")
    expect(AdvisoryImport.count).to eq(1)
    expect(AdvisoryUpload.count).to eq(0)
    expect(AuditEntry.where(action: "advisory.imported").sole).to have_attributes(actor_type: "operator", actor_id: operator.id, target_id: import.id)
    expect(VulnerabilityMatchJob).to have_been_enqueued
  end

  it "marks the import importing while it reads the file" do
    import = queued_upload(zip_bytes("DSA-9001-1.json" => osv_record(id: "DSA-9001-1")))
    seen = nil
    allow(Advisories::Reader).to receive(:new).and_wrap_original { |original, *args, **kwargs| seen = import.reload.state; original.call(*args, **kwargs) }
    run(import)
    expect(seen).to eq("importing")
  end

  it "reads a single .json file as one record" do
    import = queued_upload(JSON.generate(osv_record(id: "DSA-9001-1")), filename: "DSA-9001-1.json")
    run(import)
    expect(import.reload).to have_attributes(state: "succeeded")
    expect(Advisory.sole.advisory_id).to eq("DSA-9001-1")
  end

  it "fails the import of a file it cannot read, with the reason and no retry, and deletes the file" do
    import = queued_upload("PK\x03\x04 not a zip".b, filename: "advisories.zip")
    expect(Advisories::Reader).to receive(:new).once.and_call_original
    run(import)
    expect(import.reload).to have_attributes(state: "failed", reason: "advisories.zip is not a readable zip archive")
    expect(AdvisoryUpload.count).to eq(0)
    expect(AuditEntry.where(action: "advisory.import_failed").sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
  end

  it "retries any other failure, then fails the import with a reason, audited, deletes the file, and fails the job" do
    import = queued_upload(zip_bytes("DSA-9001-1.json" => osv_record(id: "DSA-9001-1")))
    allow(Advisories::Reader).to receive(:new).and_raise(ActiveRecord::ConnectionNotEstablished)
    expect { run(import) }.to raise_error(ActiveRecord::ConnectionNotEstablished)

    expect(Advisories::Reader).to have_received(:new).exactly(ApplicationJob::ATTEMPTS).times
    expect(import.reload).to have_attributes(state: "failed", reason: "the import failed on the server (ActiveRecord::ConnectionNotEstablished) after #{ApplicationJob::ATTEMPTS} attempts; see the failed jobs page")
    expect(AdvisoryUpload.count).to eq(0)
    expect(AuditEntry.where(action: "advisory.import_failed").sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
  end

  it "succeeds when a retry does, keeping the file until then" do
    import = queued_upload(zip_bytes("DSA-9001-1.json" => osv_record(id: "DSA-9001-1")))
    calls = 0
    allow(Advisories::Reader).to receive(:new).and_wrap_original do |original, *args, **kwargs|
      calls += 1
      expect(AdvisoryUpload.count).to eq(1)
      raise ActiveRecord::ConnectionNotEstablished if calls == 1

      original.call(*args, **kwargs)
    end
    run(import)
    expect(import.reload.state).to eq("succeeded")
    expect(AdvisoryUpload.count).to eq(0)
  end

  it "does nothing for an import that is already finished, and fails one whose file is gone" do
    done = queued_upload(zip_bytes("DSA-9001-1.json" => osv_record(id: "DSA-9001-1")))
    run(done)
    expect { run(done) }.not_to(change { [ AdvisoryImport.find(done.id).attributes, AuditEntry.count ] })

    gone = queued_upload(zip_bytes("DSA-9002-1.json" => osv_record(id: "DSA-9002-1")))
    AdvisoryUpload.delete_all
    run(gone)
    expect(gone.reload).to have_attributes(state: "failed", reason: "the uploaded file was no longer stored, so nothing was imported; upload it again")
  end

  it "writes nothing when the prune job failed the import while it was being read" do
    import = queued_upload(zip_bytes("DSA-9001-1.json" => osv_record(id: "DSA-9001-1")))
    allow(Advisories::Reader).to receive(:new).and_wrap_original do |original, *args, **kwargs|
      AdvisoryImport.where(id: import.id).update_all(state: "failed", reason: "pruned", finished_at: Time.current)
      original.call(*args, **kwargs)
    end
    run(import)
    expect(import.reload).to have_attributes(state: "failed", reason: "pruned")
    expect(Advisory.count).to eq(0)
    expect(AdvisoryUpload.count).to eq(0)
  end

  describe AdvisoryUploadPruneJob do
    it "deletes files past their expiry and fails the imports their jobs never finished, keeping a finished one's outcome" do
      now = Time.current
      stale = queued_upload("x", at: now - AdvisoryUpload::LIFETIME - 1.minute)
      fresh = queued_upload("y", at: now - 5.minutes)
      finished = AdvisoryImport.create!(origin: "file", source: "done.zip", operator:, state: "succeeded", started_at: now - 2.hours, finished_at: now - 2.hours)

      described_class.perform_now(now:)

      expect(stale.reload).to have_attributes(state: "failed")
      expect(stale.reason).to start_with("the import did not finish within 60 minutes of the upload")
      expect(fresh.reload.state).to eq("queued")
      expect(finished.reload.state).to eq("succeeded")
      expect(AdvisoryUpload.pluck(:advisory_import_id)).to eq([ fresh.id ])
      expect(AuditEntry.where(action: "advisory.import_failed").sole).to have_attributes(actor_type: "operator", actor_id: operator.id, target_id: stale.id)
    end

    it "is scheduled every 10 minutes in production" do
      schedule = YAML.safe_load_file(Rails.root.join("config/recurring.yml")).dig("production", "advisory_upload_pruning")
      expect(schedule).to eq("class" => "AdvisoryUploadPruneJob", "schedule" => "every 10 minutes")
    end
  end

  it "keeps uploads bounded in the database too" do
    import = AdvisoryImport.create!(origin: "file", source: "x.zip", operator:, state: "queued", started_at: Time.current)
    expect do
      AdvisoryUpload.create!(advisory_import: import, operator:, filename: "x.zip", byte_size: 5, data: "abc", created_at: Time.current, expires_at: 1.hour.from_now)
    end.to raise_error(ActiveRecord::StatementInvalid, /advisory_uploads_size_bounded/)
  end
end
