# The versions of each source package in the releases a fleet's backports are built from (#304, Backports): for
# Debian:14, forky's current version of each source with a Debian Security Tracker entry, the highest of its suites
# (forky, forky-security), from the tracker's "repositories". Debian refuses an upload to trixie-backports above forky's
# version once forky is released, and newer builds go to trixie-backports-sloppy, so a ~bpo13+ build above it is a
# sloppy one, matched against Debian:15 as well. Written by DebianTriage::Import, read by VulnerabilityMatcher::Chunks.
class CreateBackportSourceVersions < ActiveRecord::Migration[8.1]
  def change
    create_table :backport_source_versions, primary_key: %i[ecosystem package] do |t|
      t.string :ecosystem, limit: 64, null: false
      t.string :package, limit: 128, null: false
      t.string :version, limit: 256, null: false
      t.datetime :updated_at, null: false
    end
  end
end
