# Imports a release from GitHub for an operator (P1-S15). Enqueued by the Agents page with an
# AgentReleaseImport row; the row and the audit log, both with the operator as actor, show the outcome:
#
# - imported: the release verified and is stored (or was already, identically);
# - refused: it did not verify (Releases::Refused); final;
# - failed: GitHub has no such release, or could not be reached after the retries (NFR-2: the failure is
#   shown on the Agents page and audited, not lost).
class AgentReleaseImportJob < ApplicationJob
  queue_as :default

  ATTEMPTS = 5

  retry_on Releases::Github::Unavailable, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    job.give_up(error.message)
  end

  def perform(import_id)
    @import = AgentReleaseImport.find_by(id: import_id)
    return if @import.nil? || @import.finished?

    Current.request_id = @import.request_id
    @import.update!(state: "running") unless @import.state == "running"
    github = Releases::Github.new(@import.version)
    result = Releases::Import.new(operator: @import.operator, source: "github", expected_version: @import.version)
      .call(manifest: github.manifest, signature: github.signature) { |manifest| download(github, manifest) }
    @import.finish!("imported", release: result.release, reason: (result.created ? nil : "Already imported."))
    FleetBroadcast.refresh
  rescue Releases::Refused => e
    Releases::Import.record_refusal(operator: @import.operator, source: "github", version: @import.version, reason: e.message) do
      @import.finish!("refused", reason: e.message)
      FleetBroadcast.refresh
    end
  rescue Releases::Github::NotFound => e
    give_up(e.message)
  rescue Releases::Github::Unavailable => e
    @import.update!(reason: "#{e.message}. Retrying.")
    raise
  rescue StandardError => e
    # Anything else is a fault on this server (a full disk, a lost database connection): logged for the
    # administrator, shown to the operator, and not retried.
    logger.error("[releases] import #{import_id} of #{@import&.version} failed: #{e.class}: #{e.message}")
    give_up("the import failed on the server (#{e.class.name}); see the server log") if @import
  ensure
    @download&.close!
  end

  # Called by perform, and by retry_on once the retries are used up.
  def give_up(reason)
    @import ||= AgentReleaseImport.find(arguments.first)
    Releases::Import.record_failure(operator: @import.operator, source: "github", version: @import.version, reason:) do
      @import.finish!("failed", reason:)
      FleetBroadcast.refresh
    end
  end

  private

  # The binary, downloaded next to where it will be stored, read back from the start.
  def download(github, manifest)
    FileUtils.mkdir_p(Releases.store.dir, mode: 0o750)
    @download = Tempfile.new([ ".download-", ".part" ], Releases.store.dir, binmode: true)
    github.binary(@download, limit: manifest.size)
    @download.flush
    @download.rewind
    @download
  end
end
