# Signed agent releases on the server (P1-RELEASES, ADR 0018, ADR 0021). The format is docs/releases.md and
# the agent's verifier is agent/src/release/mod.rs; the server checks the same things in the same order, as
# defence in depth: agents never rely on it (ADR 0018).
#
# - Releases::PublicKey and Releases::Signature read minisign's .pub and .minisig formats.
# - Releases::Verifier checks a signature and the manifest it covers, then a binary against that manifest.
# - Releases::Import stores a verified release and audits it; Releases::Github fetches one for import.
# - Releases::Store keeps binaries on disk, outside the database.
module Releases
  # The only release target (DEC-01).
  TARGET = "x86_64-unknown-linux-musl".freeze
  # The manifest format this server reads, as in the agent.
  MANIFEST_FORMAT = "fleet-agent-release-manifest/1".freeze
  MAX_MANIFEST_BYTES = 4.kilobytes
  MAX_SIGNATURE_BYTES = 4.kilobytes
  MAX_BINARY_BYTES = 64.megabytes
  MAX_VERSION_LENGTH = 64

  # Why a release is not accepted. The message is a fixed sentence plus, at most, values the server parsed
  # itself (a version, a size), so it is safe to show and to audit.
  class Refused < StandardError; end

  # The configured release public keys cannot be used. Raised at boot.
  class KeyError < StandardError; end

  module_function

  def config = Rails.configuration.x.releases

  # The trusted keys: none, the current key, or the current and next keys (the rules of keys_from in
  # agent/src/release/mod.rs).
  def keys
    current = PublicKey.parse(config.current_key, role: "current")
    nxt = PublicKey.parse(config.next_key, role: "next")
    raise KeyError, "FLEET_RELEASE_KEY_NEXT is set without FLEET_RELEASE_KEY_CURRENT" if nxt && !current
    raise KeyError, "FLEET_RELEASE_KEY_CURRENT and FLEET_RELEASE_KEY_NEXT are the same key" if current && nxt && current == nxt

    [ current, nxt ].compact
  end

  def store = Store.new(config.storage_dir)

  # The agent API, as agents and the installer reach it.
  def agent_server_url = "https://#{HostSeparation.agent_host}"

  # Where a release's manifest, signature, or binary is downloaded from (P1-S16). Built in this one place so
  # the install page and, later, the update directive (P1-UPDATES) agree, and so a move to a CDN or object
  # store changes only this (ADR 0019).
  def download_url(version, file) = "#{agent_server_url}/api/v1/releases/#{version}/#{file}"

  # The file name the release workflow gives the binary (docs/releases.md); the manifest and signature add
  # .manifest.json and .manifest.json.minisig.
  def binary_name(version, target = TARGET) = "fleet-agent-#{version}-#{target}"

  # A strict SemVer version without build metadata, at most MAX_VERSION_LENGTH characters, as the agent
  # requires of a manifest (semver::Version::parse plus its own length and build-metadata checks).
  def valid_version?(version)
    version.is_a?(String) && version.length <= MAX_VERSION_LENGTH && !version.include?("+") &&
      AgentApi::AgentVersion.parse(version).present?
  end
end
