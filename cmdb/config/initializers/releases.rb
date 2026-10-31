# Signed agent releases (P1-RELEASES, ADR 0018, ADR 0021). Environment files may set any of these first; tests do.
Rails.application.configure do
  releases = config.x.releases

  # The release public keys, as the two lines of a minisign .pub file or only its base64 key line: the same
  # keys as agent/release-keys/current.pub and next.pub (docs/releases.md). The server never holds a
  # private key. Without a current key nothing can be imported.
  releases.current_key ||= ENV["FLEET_RELEASE_KEY_CURRENT"].presence
  releases.next_key ||= ENV["FLEET_RELEASE_KEY_NEXT"].presence

  # Imported binaries live here, on a persistent volume, not in the database (Active Storage is not used).
  releases.storage_dir ||= Pathname(ENV.fetch("FLEET_RELEASES_DIR") { Rails.root.join("storage/releases").to_s }).expand_path

  # Where GitHub imports come from: the release assets of the tag agent-v<version> in this repository.
  releases.github_repository ||= ENV.fetch("FLEET_RELEASE_REPOSITORY", "hostilecity/fleet-cmdb")

  # Per client address, across the unauthenticated download endpoints.
  releases.download_rate_limit ||= { to: Integer(ENV.fetch("FLEET_RELEASE_DOWNLOAD_RATE_LIMIT_PER_MINUTE", "60")), within: 1.minute }

  config.after_initialize do
    next if ENV["SECRET_KEY_BASE_DUMMY"] # the Docker build precompiles assets without runtime settings

    # A key that is set but unusable stops the boot, as the agent's build does (agent/src/release).
    Releases.keys
  end
end
