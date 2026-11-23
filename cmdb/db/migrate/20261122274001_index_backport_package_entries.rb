# Finds the stored packages that are backports (#274, Ecosystems::BACKPORTS): a change to Debian:14's advisories of a
# source re-matches only the chunks holding a backport of it (version LIKE '%~bpo13+%'), and the host tab lists a host's
# backports. Backports are a few entries per chunk at most, so this partial index stays small however many hosts there
# are, where the source index would read every chunk that has a kernel. Built concurrently: package_chunk_entries is
# the largest table.
class IndexBackportPackageEntries < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :package_chunk_entries, "COALESCE(source, name), package_chunk_id", where: "version LIKE '%~bpo%'",
                                                                                   name: "index_package_chunk_entries_on_backports", algorithm: :concurrently
  end
end
