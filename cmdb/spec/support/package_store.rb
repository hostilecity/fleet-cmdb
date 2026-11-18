# The package store (ADR 0028) is shared by every host: a spec that commits (use_transactional_tests = false) leaves
# chunks and sets behind that a later spec's identical list would reuse, with verdicts from advisories that no longer
# exist. So the store is emptied before the suite and after every such spec.
module PackageStoreHelpers
  STORE = [ ChunkMatch, ChunkEvaluation, PackageChunkEntry, PackageChunk, PackageSet ].freeze

  def self.clear! = STORE.each(&:delete_all)

  def clear_package_store! = PackageStoreHelpers.clear!

  # Holds PackageStoreBackfill's lock on a session of its own (the test's connection is shared by the pool) while the
  # block runs: another backfill, as two `docker exec` at once would be.
  def holding_backfill_lock
    info = ActiveRecord::Base.connection.raw_connection.conninfo_hash.compact.reject { |_, v| v.to_s.empty? }
    other = PG.connect(**info)
    other.exec(PackageStoreBackfill::LOCK)
    yield
  ensure
    other&.close
  end

  # The host's current packages as [name, architecture, version, source] rows.
  def stored_package_rows(host) = PackageStore.packages(HostPackageSet.find_by(host_id: host.id)&.package_set_id).map(&:to_a)
end

RSpec.configure do |config|
  config.include PackageStoreHelpers
  config.before(:suite) { PackageStoreHelpers.clear! }
  config.after { |example| PackageStoreHelpers.clear! unless example.example_group.use_transactional_tests }
end
