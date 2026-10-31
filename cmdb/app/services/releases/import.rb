module Releases
  # Imports a release (P1-S15): verifies the manifest's signature, then the binary against the manifest,
  # stores the binary, and creates the AgentRelease with its audit entry, operator as actor.
  #
  #   Releases::Import.new(operator:, source: "upload").call(manifest:, signature:) { |manifest| binary_io }
  #
  # The block is called only once the signature and manifest have verified, with the verified
  # Verifier::Manifest, and returns something to read the binary from; so a GitHub import downloads nothing
  # large for a release that is refused anyway. Raises Refused with the reason when the release is not
  # accepted; the caller audits that with Import.record_refusal (or record_failure), so it can update its own
  # records in the same transaction.
  class Import
    Result = Data.define(:release, :created)

    def initialize(operator:, source:, expected_version: nil, store: Releases.store)
      @operator = operator
      @source = source
      @expected_version = expected_version
      @store = store
    end

    def call(manifest:, signature:)
      verified = Verifier.verify_manifest(manifest, signature)
      version = verified.manifest.version
      if @expected_version && version != @expected_version
        raise Refused, "the signed manifest is for version #{version}, not #{@expected_version}"
      end

      existing = AgentRelease.find_by(version:)
      return already_imported(existing, manifest) if existing

      staged = @store.stage { |file| Verifier.check_binary(verified.manifest, yield(verified.manifest), copy_to: file) }
      begin
        create(verified, manifest, signature, staged)
      ensure
        @store.discard(staged)
      end
    end

    # Audits a refused release in a transaction of its own, then runs the block in the same transaction.
    def self.record_refusal(operator:, source:, version:, reason:, &block)
      record(Audit::Actions::RELEASE_IMPORT_REFUSED, operator:, source:, version:, reason:, &block)
    end

    # Audits an import that could not be completed for another reason (GitHub unreachable or no such release).
    def self.record_failure(operator:, source:, version:, reason:, &block)
      record(Audit::Actions::RELEASE_IMPORT_FAILED, operator:, source:, version:, reason:, &block)
    end

    def self.record(action, operator:, source:, version:, reason:)
      ApplicationRecord.transaction do
        Audit.record(actor: operator, action:, changes: { "version" => version, "source" => source, "reason" => reason }.compact)
        yield if block_given?
      end
    end
    private_class_method :record

    private

    # The same signed manifest again changes nothing. A different one for an imported version is refused: a
    # published release is never replaced (docs/releases.md).
    def already_imported(existing, manifest)
      raise Refused, "a different release #{existing.version} is already imported" unless existing.manifest == manifest.b

      Result.new(release: existing, created: false)
    end

    def create(verified, manifest, signature, staged)
      m = verified.manifest
      ApplicationRecord.transaction do
        # Serialises imports of one version, so two cannot both pass the check above and race the rename.
        ApplicationRecord.connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{ApplicationRecord.connection.quote("agent_release:#{m.version}")}))")
        existing = AgentRelease.find_by(version: m.version)
        next already_imported(existing, manifest) if existing

        @store.install(staged, m.version, m.target)
        release = AgentRelease.create!(
          version: m.version, target: m.target, sha256: m.sha256, size: m.size, manifest: manifest.b, signature: signature.b,
          trusted_comment: verified.trusted_comment, key_id: verified.key.id_hex, key_role: verified.key.role,
          source: @source, imported_by: @operator, imported_at: Time.current
        )
        Audit.record(actor: @operator, action: Audit::Actions::RELEASE_IMPORTED, target: release,
                     changes: { "version" => m.version, "sha256" => m.sha256, "size" => m.size, "key_id" => release.key_id,
                                "key_role" => release.key_role, "source" => @source })
        Result.new(release:, created: true)
      end
    end
  end
end
