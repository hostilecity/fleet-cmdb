require "rails_helper"
require "open3"

# "Install an agent" (P1-D08, FR-S.5, NFR-4, #181): the commands on the page name exactly the release shown, work as
# copied, check the release signature with the repository's public key from GitHub (never anything this server
# says), and use the real `fleet-agent install` interface (agent/src/install). The commands run here with the real
# minisign and sha256sum, and a stand-in curl that serves what the app serves on the agent hostname and what GitHub
# would serve for the key. agent/scripts/vm-test.sh runs the same commands on a Debian 13 VM.
RSpec.describe "Agent install page", :signed_in, type: :request do
  let(:agent_install_source) { Rails.root.join("../agent/src/install/mod.rs").read }
  let(:key_url) { "https://raw.githubusercontent.com/hostilecity/fleet-cmdb/refs/tags/agent-v1.2.0/agent/release-keys/current.pub" }
  let(:server) { "https://agent.fleet.example.lan" }

  before { trust_release_keys }

  def command(id) = page.at_css("##{id}").text

  # The commands a person copies on the VM, in order, after installing the tools.
  def vm_commands = %w[download_command key_command check_command].map { |id| command(id) }

  # minisign must be there in CI (server-ci.yml installs it); elsewhere these examples are skipped without it.
  def require_minisign
    return if system("minisign", "-v", out: File::NULL, err: File::NULL)
    raise "minisign is not installed, and CI needs it" if ENV["CI"]

    skip "minisign is not installed"
  end

  # A key id as the installed minisign prints it: 0.12 and later (Debian 13, and CI) with 16 digits ("%016" PRIX64),
  # as the page does; 0.11 (Debian 12) without leading zeros ("%" PRIX64) (#289).
  def minisign_key_id(id)
    version = Gem::Version.new(`minisign -v`[/\d+(\.\d+)+/])
    format(version >= Gem::Version.new("0.12") ? "%016X" : "%X", id)
  end

  # What the commands download: the app's own answers for the agent hostname; from GitHub, github_key for the key and
  # the repository's own agent/trust file for a certificate authority. replace swaps in other bytes for a URL, as a
  # hostile server (or GitHub) would.
  def web(commands, github_key: release_key.public_file, replace: {})
    commands.join("\n").scan(%r{^curl .* (https://\S+)$}).flatten.uniq.to_h do |url|
      body = case url
      when %r{\Ahttps://raw\.githubusercontent\.com/hostilecity/fleet-cmdb/refs/tags/agent-v[^/]+/agent/release-keys/current\.pub\z} then github_key
      when %r{\Ahttps://raw\.githubusercontent\.com/hostilecity/fleet-cmdb/refs/tags/agent-v[^/]+/agent/trust/([a-z-]+\.pem)\z} then Rails.root.join("../agent/trust", $1).read
      else fetch(url)
      end
      [ url, replace.fetch(url, body) ]
    end
  end

  # In a session of its own, so the page under test stays the current response.
  def fetch(url)
    uri = URI(url)
    expect(uri.host).to eq(agent_host)
    open_session do |agent|
      agent.host! agent_host
      agent.get uri.path
      expect(agent.response).to have_http_status(:ok), "#{url}: #{agent.response.status}"
      return agent.response.body.b
    end
  end

  # A curl that writes the file web holds for its URL to its -o file, and records the URL and its --cacert.
  def fake_curl(dir, web)
    site = FileUtils.mkdir_p(File.join(dir, "web")).first
    urls = web.each_with_index.map do |(url, body), i|
      File.binwrite(File.join(site, i.to_s), body)
      "#{url} #{site}/#{i}\n"
    end
    File.write(File.join(site, "urls"), urls.join)
    bin = FileUtils.mkdir_p(File.join(dir, "bin")).first
    File.write(File.join(bin, "curl"), <<~SH)
      #!/bin/sh
      out= url= ca=-
      while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift ;; --cacert) ca=$2; shift ;; https://*) url=$1 ;; esac; shift; done
      echo "$url $ca" >> "#{site}/requests"
      src=$(awk -v u="$url" '$1 == u { print $2 }' "#{site}/urls")
      [ -n "$src" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
      cp "$src" "$out"
    SH
    File.chmod(0o755, File.join(bin, "curl"))
    { "PATH" => "#{bin}:#{ENV.fetch('PATH')}" }
  end

  # Runs the commands as copied, one after another, in a fresh directory, as a person pastes them: in a plain shell,
  # without `set -e`, so the check line itself must fail closed (review of #219). The same commands under `sh -e`
  # (a script) must end the same way. Returns the plain shell's output, whether its last command (the check)
  # succeeded, and the curl requests (URL and CA file).
  def run_on_vm(commands, web)
    [ "-c", "-ec" ].map do |flags|
      Dir.mktmpdir do |dir|
        vm = FileUtils.mkdir_p(File.join(dir, "vm")).first
        env = fake_curl(dir, web).merge("TMPDIR" => vm)
        output, status = Open3.capture2e(env, "sh", flags, commands.join("\n"), chdir: vm)
        [ output, status.success?, File.readlines(File.join(dir, "web/requests"), chomp: true) ]
      end
    end.then do |plain, script|
      expect(script).to eq(plain)
      plain
    end
  end

  # The cloud-init command, parsed as cloud-init parses it.
  def cloud_init = YAML.safe_load(command("cloud_init"))

  def cloud_init_argv = cloud_init["runcmd"].sole

  def cloud_init_script = cloud_init_argv.last.lines.map(&:chomp)

  # Runs the cloud-init script as cloud-init would (its argv, as written on the page), with /root moved to a scratch
  # directory. Returns whether the downloaded binary ran, and whether the script succeeded.
  def run_cloud_init(web)
    Dir.mktmpdir do |dir|
      root = FileUtils.mkdir_p(File.join(dir, "root")).first
      *shell, script = cloud_init_argv
      env = fake_curl(dir, web).merge("MARKER" => File.join(dir, "ran"))
      _output, status = Open3.capture2e(env, *shell, script.sub("cd /root\n", "cd #{root}\n"))
      [ File.exist?(File.join(dir, "ran")), status.success? ]
    end
  end

  it "says what to do when no release has been imported" do
    get "/agents/install"
    expect(response).to have_http_status(:ok)
    expect(page.at_css("#no_release").text).to include("Import a signed release on the Agents page first")
    expect(page.css(".token")).to be_empty
  end

  it "shows the commands for the current release, with the key from the repository on GitHub at its tag" do
    import_release(signed_release(version: "1.1.0"), operator:)
    import_release(signed_release(version: "1.2.0"), operator:)
    import_release(signed_release(version: "1.3.0-rc.1"), operator:) # pre-releases are not offered by default

    get "/agents/install"
    expect(page.at_css("#release_version").text).to eq("1.2.0")
    expect(command("tools_command")).to eq("sudo apt-get update && sudo apt-get install -y curl minisign && sudo -k")
    expect(command("download_command")).to eq(<<~SH.chomp)
      cd "$(mktemp -d)"
      curl -fL -o fleet-agent #{server}/api/v1/releases/1.2.0/binary
      curl -fL -o fleet-agent.manifest.json #{server}/api/v1/releases/1.2.0/manifest
      curl -fL -o fleet-agent.manifest.json.minisig #{server}/api/v1/releases/1.2.0/signature
    SH
    expect(command("key_command")).to eq("curl -fsSL -o fleet-release-key.pub #{key_url}")
    expect(command("check_command")).to eq(%(minisign -V -p fleet-release-key.pub -m fleet-agent.manifest.json -o | sed -n 's/^{"format":"fleet-agent-release-manifest\\/1","version":"1\\.2\\.0","target":"x86_64-unknown-linux-musl","sha256":"\\([0-9a-f]\\{64\\}\\)","size":[0-9]*}$/\\1  fleet-agent/p' | sha256sum -c))
    expect(command("check_output")).to eq("Signature and comment signature verified\nTrusted comment: fleet-agent 1.2.0 x86_64-unknown-linux-musl release manifest\nfleet-agent: OK")
    expect(command("install_command")).to eq("chmod +x fleet-agent && sudo ./fleet-agent install --server #{server}")
    expect(command("token_command")).to eq("chmod +x fleet-agent && sudo ./fleet-agent install --server #{server} --token-stdin")
    expect(page.text).not_to match(/\b\h{64}\b/) # no checksum from this server to compare against
    docs = Rails.root.join("../docs/operations/install-agent.md").read
    expect(docs).to include(command("tools_command"), command("key_command"), command("check_command"), *command("check_output").lines.map(&:chomp)) # the guide shows the same
    expect(command("compare_with_guide")).to include("open the install guide on GitHub yourself, not from a link here", "github.com/hostilecity/fleet-cmdb",
                                                     "before you press Enter, check what you pasted in the terminal against the guide")
    expect(page.at_css("#compare_with_guide a")).to be_nil # no server-rendered link to the guide
    expect(command("check_failed")).to include("Do not run the agent: delete the files and start again. If it fails again, treat the server as suspect.")
    expect(docs).to include("Do not run the agent: delete the files and start again. If it fails again, treat the server as suspect.")
  end

  it "shows the key the check trusts, and no warning while this server's keys are the repository's" do
    import_release(signed_release(version: "1.2.0"), operator:)
    get "/agents/install"
    expect(page.at_css("#release_key_warning")).to be_nil
    expect(command("release_key_line")).to eq(release_key.public_line)
    expect(command("release_key")).to include("hostilecity/fleet-cmdb at the tag agent-v1.2.0 on GitHub", "signed with key #{release_key.id_hex}",
                                              "the repository's current key", "docs/releases.md")
  end

  describe "the check, run as copied with the real minisign" do
    before { require_minisign }

    it "passes for the release as signed, printing exactly what the page says, and fetches the key only from GitHub" do
      import_release(release = signed_release(version: "1.2.0"), operator:)
      get "/agents/install"
      output, ok, requests = run_on_vm(vm_commands, web(vm_commands))
      expect([ output, ok ]).to eq([ "#{command('check_output')}\n", true ])
      downloads = %w[binary manifest signature].map { |file| "#{server}/api/v1/releases/1.2.0/#{file}" }
      expect(requests.map { |line| line.split.first }).to eq(downloads + [ key_url ])
      expect(fetch(downloads.first)).to eq(release.binary)
    end

    it "refuses a tampered binary" do
      import_release(release = signed_release(version: "1.2.0"), operator:)
      get "/agents/install"
      binary = "#{server}/api/v1/releases/1.2.0/binary"
      [ release.binary.succ, release.binary.byteslice(0, 100), "", signed_release(version: "1.2.0").binary ].each do |tampered|
        output, ok, = run_on_vm(vm_commands, web(vm_commands, replace: { binary => tampered }))
        expect(ok).to be(false)
        expect(output).to include("fleet-agent: FAILED")
        expect(output).not_to include("fleet-agent: OK")
      end
    end

    # Fixed ids, not random ones, so an id that starts with 0 is always checked: the page names the key with all 16
    # digits, as minisign 0.12 on Debian 13 does, and minisign 0.11 prints it without leading zeros (#289).
    { 0x0A2E8E1D2E10F3B9 => "0A2E8E1D2E10F3B9", 0x9E62E8E1D2E10F3B => "9E62E8E1D2E10F3B" }.each do |id, shown|
      it "refuses a manifest signed by a key other than the repository's, even one this server was set to trust (key #{shown})" do
        attacker = TestReleaseKey.with_id(id)
        trust_release_keys(current: attacker)
        publish_repository_keys(current: release_key)
        import_release(signed_release(version: "1.2.0", key: attacker), operator:)
        get "/agents/install"
        expect(page.at_css("#release_key_warning").text).to include("FLEET_RELEASE_KEY_CURRENT differs from the repository's", "treat this server as compromised")
        expect(command("release_key")).to include("signed with key #{shown},", "not one of the keys in this server's copy of the repository")
        output, ok, = run_on_vm(vm_commands, web(vm_commands, github_key: release_key.public_file))
        expect(ok).to be(false)
        expect(output).to include("Signature key id in fleet-agent.manifest.json.minisig is #{minisign_key_id(id)}\n")
        expect(output).not_to include("fleet-agent: OK")
      end
    end

    it "refuses a changed manifest under the release's own signature" do
      import_release(release = signed_release(version: "1.2.0"), operator:)
      get "/agents/install"
      other = SecureRandom.bytes(4096)
      changed = manifest_json(version: "1.2.0", binary: other)
      replace = { "#{server}/api/v1/releases/1.2.0/manifest" => changed, "#{server}/api/v1/releases/1.2.0/binary" => other }
      output, ok, = run_on_vm(vm_commands, web(vm_commands, replace:))
      expect(ok).to be(false)
      expect(output).to include("Signature verification failed")
      expect(output).not_to include("fleet-agent: OK")
      expect(release.manifest).not_to eq(changed)
    end

    it "refuses an older release, signed with the same key, served under this release's URLs (review of #219)" do
      older = signed_release(version: "1.1.0")
      import_release(signed_release(version: "1.2.0"), operator:)
      get "/agents/install"
      files = { "binary" => older.binary, "manifest" => older.manifest, "signature" => older.signature }
      replace = files.transform_keys { |what| "#{server}/api/v1/releases/1.2.0/#{what}" }
      output, ok, = run_on_vm(vm_commands, web(vm_commands, replace:))
      expect(ok).to be(false)
      expect(output).to include("Trusted comment: fleet-agent 1.1.0 ", "no properly formatted checksum lines found")
      expect(output).not_to include("fleet-agent: OK")
      expect(run_cloud_init(web(cloud_init_script, replace:))).to eq([ false, false ])
    end

    it "passes for a release signed with the repository's next key, which is current.pub at that release's tag" do
      trust_release_keys(current: release_key, next_key: next_release_key)
      import_release(signed_release(version: "1.2.0", key: next_release_key), operator:)
      get "/agents/install"
      expect(page.at_css("#release_key_warning")).to be_nil
      expect(command("release_key")).to include("signed with key #{next_release_key.id_hex}", "the repository's next key")
      output, ok, = run_on_vm(vm_commands, web(vm_commands, github_key: next_release_key.public_file))
      expect([ output, ok ]).to eq([ "#{command('check_output')}\n", true ])
    end

    it "never runs a cloud-init download that fails the check, and runs one that passes (review of #74)" do
      binary = %(#!/bin/sh\ntouch "$MARKER"\n)
      import_release(release = signed_release(version: "1.2.0", binary:), operator:)
      get "/agents/install"
      expect(cloud_init_argv.first(2)).to eq([ "sh", "-ec" ])
      script = cloud_init_script
      binary_url = "#{server}/api/v1/releases/1.2.0/binary"
      expect(run_cloud_init(web(script))).to eq([ true, true ])
      expect(run_cloud_init(web(script, replace: { binary_url => binary.sub("touch", "touch  ") }))).to eq([ false, false ]) # tampered
      expect(run_cloud_init(web(script, replace: { binary_url => "" }))).to eq([ false, false ]) # empty or truncated download
      expect(run_cloud_init(web(script, github_key: next_release_key.public_file))).to eq([ false, false ]) # another key
      expect(release.binary).to eq(binary)
    end
  end

  it "warns when this server's keys differ from the repository's, naming each" do
    trust_release_keys(current: release_key, next_key: next_release_key)
    publish_repository_keys(current: release_key, next_key: TestReleaseKey.new)
    import_release(signed_release(version: "1.2.0"), operator:)
    get "/agents/install"
    expect(page.at_css("#release_key_warning").text).to include("FLEET_RELEASE_KEY_NEXT differs from the repository's")
    publish_repository_keys(current: TestReleaseKey.new, next_key: nil)
    get "/agents/install"
    expect(page.at_css("#release_key_warning").text).to include("FLEET_RELEASE_KEY_CURRENT and FLEET_RELEASE_KEY_NEXT differ from the repository's")
  end

  it "names exactly the release it links to in every command, for any imported release" do
    releases = %w[1.1.0 1.2.0 1.3.0-rc.1].map { |version| import_release(signed_release(version:), operator:) }
    releases.each do |release|
      get "/agents/install", params: { version: release.version }
      expect(page.at_css("#release_version").text).to eq(release.version)
      urls = [ *vm_commands, *cloud_init_script ].join("\n").scan(%r{^curl .* (https://\S+)$}).flatten
      expect(urls.size).to eq(8)
      expect(urls).to all(include("/api/v1/releases/#{release.version}/").or(include("/refs/tags/agent-v#{release.version}/")))
      expect(command("check_output")).to include("Trusted comment: fleet-agent #{release.version} ")
      expect(page.text.include?("(a pre-release)")).to eq(release.prerelease?)
    end
  end

  it "answers 404 for a version that is not imported" do
    get "/agents/install", params: { version: "9.9.9" }
    expect(response).to have_http_status(:not_found)
  end

  it "uses only options the installer has (agent/src/install/mod.rs), and its token environment variable" do
    import_release(signed_release(version: "1.2.0"), operator:)
    get "/agents/install"
    known = agent_install_source[/const KNOWN_OPTIONS: &\[&str\] = &\[(.*?)\];/m, 1].scan(/"([^"]+)"/).flatten
    expect(known).to include("--server", "--token-stdin", "--quiet")
    script = cloud_init_script
    commands = [ command("install_command"), command("token_command"), *script ]
    install_flags = commands.grep(/fleet-agent install/).flat_map { |line| line[/fleet-agent install (.*)/, 1].scan(/(?<=\s|\A)--[a-z-]+/) }
    expect(install_flags.uniq).to contain_exactly("--server", "--token-stdin", "--quiet")
    expect(install_flags - known).to eq([])
    expect(agent_install_source).to include('std::env::var("FLEET_ENROLLMENT_TOKEN")')
    expect(cloud_init.keys).to eq(%w[package_update packages runcmd])
    expect(cloud_init.slice("package_update", "packages")).to eq("package_update" => true, "packages" => %w[curl minisign])
    expect(script.first).to eq("cd /root")
    expect(script.last(2)).to eq([ "chmod +x fleet-agent", "FLEET_ENROLLMENT_TOKEN='<one-time token>' ./fleet-agent install --server #{server} --quiet" ])
    expect(script[1..-3]).to eq(vm_commands.join("\n").lines.drop(1).map(&:chomp)) # the same download and check as one VM, in /root
    expect(command("cloud_init")).to start_with("#cloud-config\n")
  end

  describe "with a server certificate from Cloudflare's Origin CA (ADR 0024)" do
    let(:ca_url) { "https://raw.githubusercontent.com/hostilecity/fleet-cmdb/refs/tags/agent-v1.2.0/agent/trust/cloudflare-origin-ecc.pem" }

    around do |example|
      saved = Rails.configuration.x.server_tls_root_file
      Rails.configuration.x.server_tls_root_file = "cloudflare-origin-ecc.pem"
      example.run
    ensure
      Rails.configuration.x.server_tls_root_file = saved
    end

    it "fetches that certificate authority from the repository on GitHub, for the downloads from this server only" do
      require_minisign
      import_release(signed_release(version: "1.2.0"), operator:)
      get "/agents/install"
      download = command("download_command")
      files = { "binary" => "fleet-agent", "manifest" => "fleet-agent.manifest.json", "signature" => "fleet-agent.manifest.json.minisig" }
      expect(download.lines.map(&:chomp)).to eq([ %(cd "$(mktemp -d)"), "curl -fsSL -o fleet-server-ca.pem #{ca_url}",
                                                  *files.map { |what, file| "curl -fL --cacert fleet-server-ca.pem -o #{file} #{server}/api/v1/releases/1.2.0/#{what}" } ])
      expect(page.text).not_to include("BEGIN CERTIFICATE") # nothing opaque from this server to paste
      expect(vm_commands.join).not_to include("update-ca-certificates", "--insecure", " -k ")
      output, ok, requests = run_on_vm(vm_commands, web(vm_commands))
      expect([ output, ok ]).to eq([ "#{command('check_output')}\n", true ])
      expected = files.keys.to_h { |what| [ "#{server}/api/v1/releases/1.2.0/#{what}", "fleet-server-ca.pem" ] }
      expect(requests.to_h(&:split)).to eq({ ca_url => "-" }.merge(expected, key_url => "-")) # GitHub is checked against the system store
      expect(cloud_init_script[1]).to eq("curl -fsSL -o fleet-server-ca.pem #{ca_url}")
      # The guide shows these commands, with its example server.
      docs = Rails.root.join("../docs/operations/install-agent.md").read
      expect(docs).to include(*download.gsub(server, "https://fleet-vm.example.com").lines.map(&:chomp))
    end

    it "is what agent/scripts/vm-test.sh runs on a Debian 13 VM, word for word" do
      import_release(signed_release(version: "1.2.0"), operator:)
      get "/agents/install"
      vm_test = Rails.root.join("../agent/scripts/vm-test.sh").read
      tools = vm_test[/^INSTALL_TOOLS='(.*)'$/, 1]
      block = vm_test[/^install_commands\(\) \{\n.*?cat << EOF\n(.*?)^EOF\n/m, 1]
      expect(tools).to eq(ApplicationController.helpers.install_tools_command(sudo: false))
      # An unquoted heredoc expands only $s (the server), $n (the stub's release, in place of the version in URLs),
      # and $e (the version, escaped for sed) here; its backslashes stay as written. The VM test writes the CA file
      # (a throwaway CA, not on GitHub) into a root-only directory of its own instead of the first two lines.
      expanded = block.gsub("$s", server).gsub("$n", "1.2.0").gsub("$e", "1\\.2\\.0")
      expect(expanded).to eq([ *command("download_command").lines.last(3).map(&:chomp), command("check_command") ].join("\n") + "\n")
      expect(vm_test).to include(%(scenario 290 "First install refuses a tampered binary, another key, and an older release (#181)" install_refusals))
    end
  end

  it "shows what the installer prints for approval, as the installer prints it (agent/src/install/ui.rs)" do
    import_release(signed_release(version: "1.2.0"), operator:)
    get "/agents/install"
    ui = Rails.root.join("../agent/src/install/ui.rs").read
    example = command("approval_example")
    pad = ui[/const PAD: &str = "( +)";/, 1]
    expect(example.lines.first).to eq("#{pad}An operator must approve this VM in the dashboard. Open this page, signed in:\n")
    [ "An operator must approve this VM in the dashboard. Open this page, signed in:", "and check that it shows this code:",
      "Press Ctrl-C to cancel; nothing is enrolled until it is approved." ].each do |text|
      expect(ui).to include(text)
      expect(example).to include(text)
    end
    expect(example).to include("#{pad}    https://fleet.example.lan/onboard/WDJB-MJHT\n", "#{pad}    WDJB-MJHT\n", "The request expires in 10 minutes.")
    expect(page.at_css("a[href='/onboard']")).to be_present
  end

  it "adds the same download and check to a pre-registered host's one-time token page" do
    import_release(signed_release(version: "1.2.0"), operator:)
    get "/agents/install"
    commands = vm_commands
    post "/hosts", params: { host: { name: "Lab sandbox", hostname: "vm-06.example.lan" } }
    tokens = page.css(".token").map(&:text)
    expect(tokens).to include("apt-get update && apt-get install -y curl minisign", *commands)
  end

  it "links a pre-registered host's token page to this page while no release is imported" do
    post "/hosts", params: { host: { name: "Lab sandbox", hostname: "vm-06.example.lan" } }
    expect(page.at_css("a[href='/agents/install']").text).to eq("Install an agent")
  end
end
