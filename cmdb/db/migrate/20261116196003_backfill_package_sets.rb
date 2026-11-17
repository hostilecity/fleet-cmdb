# Moves the stored package lists into content-addressed sets (#196, ADR 0028, "Migration from the current schema"),
# in batches of BATCH, each its own short transaction, so it holds no long lock and can be run again after a failure
# (only rows with no set yet are read).
#
# - Hosts: only dpkg hosts are grouped. Hosts with the same host_package_sets.content_hash and a dpkg manager have the
#   same list, so the set is stored once per hash from one host's host_packages rows, and every such host points at it.
# - An unreadable host's set is built from its own host_packages rows: its content_hash hashes only the manager and
#   reason (AgentApi::PackageReport#content_hash), while PackageRecorder kept its previous rows, so unreadable hosts
#   with one reason share a hash but not a list. One that was never readable (no rows) gets no set. An unsupported
#   host gets no set.
# - Snapshots: every dpkg snapshot gets the set of its JSON list, once per content hash (the snapshot hash covers the
#   list, so one hash is one list). That includes each host's newest snapshot, which retention keeps however old.
#   Unsupported and unreadable snapshots have no list and get no set.
# - Findings: last_source, last_installed_version, and last_fixed_version take the finding's current details, which
#   are shown until its host's chunks are matched (lazily, at its next transitions; ADR 0028 decision 7).
#
# It uses PackageStore, so the sets it stores hash exactly as a package report's would. DropHostPackages then refuses
# to drop the old storage while any dpkg snapshot or host is left without a set.
class BackfillPackageSets < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  BATCH = 1_000
  Package = AgentApi::PackageReport::Package

  def up
    each_batch("SELECT DISTINCT content_hash FROM host_package_sets WHERE manager = 'dpkg' AND package_set_id IS NULL") do |hash|
      host_id = select_value("SELECT host_id FROM host_package_sets WHERE manager = 'dpkg' AND content_hash = #{quote(hash)} LIMIT 1")
      set_id = PackageStore.store!(host_rows(host_id))
      execute "UPDATE host_package_sets SET package_set_id = #{set_id} WHERE manager = 'dpkg' AND content_hash = #{quote(hash)} AND package_set_id IS NULL"
    end
    each_batch("SELECT host_id FROM host_package_sets WHERE manager = 'unreadable' AND package_set_id IS NULL " \
               "AND EXISTS (SELECT 1 FROM host_packages p WHERE p.host_id = host_package_sets.host_id)") do |host_id|
      execute "UPDATE host_package_sets SET package_set_id = #{PackageStore.store!(host_rows(host_id))} WHERE host_id = #{Integer(host_id)}"
    end
    each_batch("SELECT DISTINCT content_hash FROM package_snapshots WHERE manager = 'dpkg' AND package_set_id IS NULL") do |hash|
      json = select_value("SELECT packages FROM package_snapshots WHERE manager = 'dpkg' AND content_hash = #{quote(hash)} LIMIT 1")
      set_id = PackageStore.store!(JSON.parse(json).map { |row| Package.from_a(row) })
      execute "UPDATE package_snapshots SET package_set_id = #{set_id} WHERE manager = 'dpkg' AND content_hash = #{quote(hash)} AND package_set_id IS NULL"
    end
    execute "UPDATE vulnerability_findings SET last_source = source, last_installed_version = installed_version, last_fixed_version = fixed_version"
  end

  def down
    execute "UPDATE host_package_sets SET package_set_id = NULL"
    execute "UPDATE package_snapshots SET package_set_id = NULL"
    %w[chunk_matches chunk_evaluations package_sets package_chunk_entries package_chunks].each { |table| execute "DELETE FROM #{table}" }
  end

  private

  def host_rows(host_id)
    select_rows("SELECT name, architecture, version, source FROM host_packages WHERE host_id = #{Integer(host_id)}").map { |row| Package.from_a(row) }
  end

  # Yields each value the query selects, BATCH to a transaction. The query is run again for each batch: what a batch
  # has stored no longer matches it.
  def each_batch(sql)
    loop do
      values = select_values("#{sql} LIMIT #{BATCH}")
      break if values.empty?

      transaction { values.each { |value| yield value } }
    end
  end
end
