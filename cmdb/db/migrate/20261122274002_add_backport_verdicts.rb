# Backport verdicts (#274, Backports): from_fixed_version is the fix in the release a backport is built from
# (Debian:14's), shown but never counted as a fix for the host's release, since this server cannot tell whether
# trixie-backports has a build at or above it; keep_only marks a verdict that keeps an existing finding open (and
# triaged) but never opens or reopens one: only the release's own data says the backport is fixed, and the release it
# is built from has no data for its source. Both are written by VulnerabilityMatcher::Chunks. Constant defaults, so
# adding them rewrites nothing.
class AddBackportVerdicts < ActiveRecord::Migration[8.1]
  def change
    add_column :chunk_matches, :from_fixed_version, :string, limit: 256
    add_column :chunk_matches, :keep_only, :boolean, null: false, default: false
  end
end
