# A signed agent release the server has verified and stores (P1-RELEASES, ADR 0018). Create one only through
# Releases::Import, which verifies it and audits the import. Releases are immutable, and never deleted while
# a host in the fleet runs them (also enforced by the agent_releases_guard database trigger).
class AgentRelease < ApplicationRecord
  class InUse < StandardError; end

  SOURCES = %w[github upload].freeze

  belongs_to :imported_by, class_name: "Operator"

  validates :version, presence: true, uniqueness: true
  validates :source, inclusion: { in: SOURCES }
  validates :key_role, inclusion: { in: %w[current next] }

  before_destroy :refuse_while_in_use

  # Newest first by SemVer precedence. Releases are few, so they are sorted here rather than in SQL.
  def self.newest_first = all.to_a.sort_by(&:semver).reverse

  # What the install page offers: the newest release that is not a pre-release.
  def self.current = newest_first.find { |release| !release.prerelease? }

  def semver = AgentApi::AgentVersion.parse(version)

  def prerelease? = semver.prerelease.any?

  def binary_name = Releases.binary_name(version, target)

  def manifest_name = "#{binary_name}.manifest.json"

  def signature_name = "#{manifest_name}.minisig"

  def binary_path = Releases.store.path(version, target)

  # Hosts in the fleet that last reported running this version.
  def hosts_running = Host.in_fleet.where(agent_version: version)

  def in_use? = hosts_running.exists?

  private

  # Rollouts that target a release (P1-UPDATES) will refuse deletion too.
  def refuse_while_in_use
    raise InUse, "agent release #{version} is in use by a host and cannot be deleted" if in_use?
  end
end
