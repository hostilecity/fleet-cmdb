# The install commands (P1-D08) and release display helpers. Every command is built from one AgentRelease, so
# the URL, the checksum, and the version on the page always belong to the same release. The flags are those
# of `fleet-agent install` (agent/src/install/mod.rs, INSTALL_USAGE).
module AgentReleasesHelper
  # The file name the commands save the binary as.
  INSTALL_FILE = "fleet-agent".freeze
  # Shown where a pre-registered host's token goes. Not a valid token, so a command copied without
  # replacing it fails on the VM before contacting the server.
  TOKEN_PLACEHOLDER = "<one-time token>".freeze

  def install_download_command(release, file: INSTALL_FILE)
    "curl -fL -o #{file} #{Releases.download_url(release.version, 'binary')}"
  end

  # Two spaces between checksum and name, as sha256sum -c requires.
  def install_check_command(release, file: INSTALL_FILE)
    %(echo "#{release.sha256}  #{file}" | sha256sum -c)
  end

  def install_run_command(sudo: true)
    "chmod +x #{INSTALL_FILE} && #{'sudo ' if sudo}./#{INSTALL_FILE} install --server #{Releases.agent_server_url}"
  end

  def install_token_command(sudo: true)
    "#{install_run_command(sudo:)} --token-stdin"
  end

  # cloud-init runs commands as root, from /, so the binary goes in /root and there is no sudo.
  def install_cloud_init(release, token: TOKEN_PLACEHOLDER)
    file = "/root/#{INSTALL_FILE}"
    <<~YAML
      #cloud-config
      runcmd:
        - #{install_download_command(release, file:)}
        - #{install_check_command(release, file:)}
        - chmod +x #{file}
        - FLEET_ENROLLMENT_TOKEN='#{token}' #{file} install --server #{Releases.agent_server_url} --quiet
    YAML
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
