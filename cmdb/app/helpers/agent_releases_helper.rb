# The install commands (P1-D08, #181) and release display helpers. Every command is built from one AgentRelease, so
# the URLs and the version on the page always belong to the same release. The binary is checked against the release
# signature, with the public key from the repository on GitHub, never against anything this server says. The flags
# are those of `fleet-agent install` (agent/src/install/mod.rs, INSTALL_USAGE).
module AgentReleasesHelper
  # The file names the commands save the binary, its signed manifest, the manifest's signature, and the release
  # public key as. The signature is named as minisign looks for it (the manifest's name plus .minisig).
  INSTALL_FILE = "fleet-agent".freeze
  INSTALL_MANIFEST_FILE = "fleet-agent.manifest.json".freeze
  INSTALL_SIGNATURE_FILE = "#{INSTALL_MANIFEST_FILE}.minisig".freeze
  INSTALL_KEY_FILE = "fleet-release-key.pub".freeze
  # The file the download command writes the server's certificate authority to, when curl needs it (ADR 0024).
  INSTALL_CA_FILE = "fleet-server-ca.pem".freeze
  # The Debian packages the commands use (both are in Debian and most other distributions).
  INSTALL_PACKAGES = %w[curl minisign].freeze
  # Shown where a pre-registered host's token goes. Not a valid token, so a command copied without
  # replacing it fails on the VM before contacting the server.
  TOKEN_PLACEHOLDER = "<one-time token>".freeze

  def install_tools_command(sudo: true)
    prefix = "sudo " if sudo
    "#{prefix}apt-get update && #{prefix}apt-get install -y #{INSTALL_PACKAGES.join(' ')}"
  end

  # The binary, its manifest, and the manifest's signature, from this server. With a server certificate from a
  # certificate authority curl does not know (Cloudflare's Origin CA, ADR 0024), the command first writes that
  # authority's certificate (Rails.configuration.x.server_tls_root, public) next to them and gives it to curl, so
  # the download is verified without changing the VM's trust store. Nothing here is trusted because of where it
  # came from: the check command (below) is what vouches for the binary.
  def install_download_command(release)
    root = Rails.configuration.x.server_tls_root
    curl = root ? "curl -fL --cacert #{INSTALL_CA_FILE}" : "curl -fL"
    downloads = { INSTALL_FILE => "binary", INSTALL_MANIFEST_FILE => "manifest", INSTALL_SIGNATURE_FILE => "signature" }
      .map { |file, what| "#{curl} -o #{file} #{Releases.download_url(release.version, what)}" }
    [ ("cat > #{INSTALL_CA_FILE} <<'EOF'\n#{root.strip}\nEOF" if root), *downloads ].compact.join("\n")
  end

  # The release public key, from the repository on GitHub at the release's tag, not from this server (#181).
  def install_key_command(release)
    "curl -fsSL -o #{INSTALL_KEY_FILE} #{Releases.public_key_url(release.version)}"
  end

  # Checks the manifest's signature with that key, then the binary against the SHA-256 in the manifest minisign
  # has just verified (-o prints the verified manifest, and nothing if the signature does not verify). Any
  # failure, including a wrong key, a changed manifest, or a changed binary, makes sha256sum fail, so the
  # pipeline's status is the check's: it prints "fleet-agent: OK" only for a binary of a signed release. The
  # pattern reads one line of JSON in the release workflow's fixed format (docs/releases.md).
  def install_check_command
    %(minisign -V -p #{INSTALL_KEY_FILE} -m #{INSTALL_MANIFEST_FILE} -o | sed -n 's/.*"sha256":"\\([0-9a-f]\\{64\\}\\)".*/\\1  #{INSTALL_FILE}/p' | sha256sum -c)
  end

  # What a passing check prints: minisign's two lines (with the release's own trusted comment), then sha256sum's.
  def install_check_output(release)
    "Signature and comment signature verified\nTrusted comment: #{release.trusted_comment}\n#{INSTALL_FILE}: OK"
  end

  def install_run_command(sudo: true)
    "chmod +x #{INSTALL_FILE} && #{'sudo ' if sudo}./#{INSTALL_FILE} install --server #{Releases.agent_server_url}"
  end

  def install_token_command(sudo: true)
    "#{install_run_command(sudo:)} --token-stdin"
  end

  # cloud-init runs commands as root, from /, so the script works in /root and there is no sudo. curl and
  # minisign come from cloud-init's packages module, which runs before runcmd.
  #
  # The steps are one `sh -ec` script, not one runcmd entry each: cloud-init joins runcmd entries into a plain
  # #!/bin/sh script without `set -e`, so a failed check would not stop it, and the unverified download
  # would then run as root (review of #74). With -e, any failing step stops the script before the binary runs.
  def install_cloud_init(release, token: TOKEN_PLACEHOLDER)
    script = install_cloud_init_script(release, token:).flat_map { |command| command.split("\n") }.map { |line| "      #{line}\n" }.join
    packages = INSTALL_PACKAGES.map { |name| "  - #{name}\n" }.join
    "#cloud-config\npackage_update: true\npackages:\n#{packages}runcmd:\n  - - sh\n    - -ec\n    - |\n#{script}"
  end

  def install_cloud_init_script(release, token: TOKEN_PLACEHOLDER)
    [ "cd /root",
      install_download_command(release),
      install_key_command(release),
      install_check_command,
      "chmod +x #{INSTALL_FILE}",
      "FLEET_ENROLLMENT_TOKEN='#{token}' ./#{INSTALL_FILE} install --server #{Releases.agent_server_url} --quiet" ]
  end

  # The installer's approval block, as it prints it (agent/src/install/ui.rs, Ui::approval), with an example
  # code.
  def install_approval_example
    pad = " " * 6
    code = "WDJB-MJHT"
    [ "#{pad}An operator must approve this VM in the dashboard. Open this page, signed in:", "",
      "#{pad}    #{OnboardingRequest.verification_uri}/#{code}", "",
      "#{pad}and check that it shows this code:", "",
      "#{pad}    #{code}", "",
      "#{pad}The request expires in #{OnboardingRequest.config.ttl.in_minutes.to_i} minutes. Press Ctrl-C to cancel; nothing is enrolled until it is approved." ].join("\n")
  end

  def release_key_label(release)
    "#{release.key_role} key #{release.key_id}"
  end

  IMPORT_STATES = {
    "queued" => [ "Queued", "awaiting" ],
    "running" => [ "Importing", "awaiting" ],
    "imported" => [ "Imported", "online" ],
    "refused" => [ "Refused", "offline" ],
    "failed" => [ "Failed", "offline" ]
  }.freeze

  def import_state_lamp(import)
    label, lamp = IMPORT_STATES.fetch(import.state)
    tag.span(label, class: [ "lamp", lamp ])
  end
end
