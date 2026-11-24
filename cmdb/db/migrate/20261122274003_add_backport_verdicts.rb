# Backport verdicts (#274, Backports): from_fixed_version is the fix in the release a backport is built from
# (Debian:14's), shown but never counted as a fix for the host's release, since this server cannot tell whether
# trixie-backports has a build at or above it; keep_only marks a verdict that keeps an existing finding open (and
# triaged), or reopens one resolved as fixed, but never opens one: only the release's own data says the backport is fixed, and the release it
# is built from has no data for its source. Both are written by VulnerabilityMatcher::Chunks. Constant defaults, so
# adding them rewrites nothing. A version of its own, and if_not_exists, since 20261122274002 was another migration at
# an earlier head of #294 (review of #294, N4): a database that ran it gets the columns, one that has them is left as
# it is.
class AddBackportVerdicts < ActiveRecord::Migration[8.1]
  def change
    add_column :chunk_matches, :from_fixed_version, :string, limit: 256, if_not_exists: true
    add_column :chunk_matches, :keep_only, :boolean, null: false, default: false, if_not_exists: true
  end
end
