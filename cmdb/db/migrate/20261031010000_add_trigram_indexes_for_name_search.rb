# Substring search (the fleet search and the audit log's target and actor filters, P1-AUDIT-PAGE) matches
# with ILIKE '%text%', which a btree index cannot serve, so every such request read the whole hosts table:
# about 440 ms at a million hosts. Trigram GIN indexes serve the same ILIKE patterns unchanged (about 5 ms
# there), so no query changes. pg_trgm is a trusted extension, shipped with Debian's postgresql package
# (review of #71). Built concurrently, so hosts keep reporting while they build.
class AddTrigramIndexesForNameSearch < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    enable_extension "pg_trgm"
    add_index :hosts, :name, using: :gin, opclass: :gin_trgm_ops, name: "index_hosts_on_name_trigram", algorithm: :concurrently
    add_index :hosts, :hostname, using: :gin, opclass: :gin_trgm_ops, name: "index_hosts_on_hostname_trigram", algorithm: :concurrently
    add_index :operators, :email, using: :gin, opclass: :gin_trgm_ops, name: "index_operators_on_email_trigram", algorithm: :concurrently
  end
end
