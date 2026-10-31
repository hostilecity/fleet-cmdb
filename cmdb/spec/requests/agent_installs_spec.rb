require "rails_helper"
require "open3"

# "Install an agent" (P1-D08, FR-S.5, NFR-4): the commands on the page name exactly the release shown, work as
# copied, and use the real `fleet-agent install` interface (agent/src/install). Running them on a clean
# Debian 13 VM is part of P1-ACCEPT.
RSpec.describe "Agent install page", type: :request do
  let(:operator) { Operator.find_by!(email: "operator@example.com") }
  let(:agent_install_source) { Rails.root.join("../agent/src/install/mod.rs").read }

  before do
    trust_release_keys
    sign_in_operator
  end

  def page = Nokogiri::HTML(response.body)

  def command(id) = page.at_css("##{id}").text

  # Fetches what the download command fetches, from the app on the agent hostname.
  def fetch_download(download_command)
    url = URI(download_command[%r{https://\S+}])
    expect(url.host).to eq(agent_host)
    host! agent_host
    get url.path
    host! dashboard_host
    response.body.b
  end

  # Runs the check command as copied, in a directory holding the downloaded file.
  def run_check(check_command, binary)
    Dir.mktmpdir do |dir|
      File.binwrite(File.join(dir, "fleet-agent"), binary)
      Open3.capture2e("bash", "-c", check_command, chdir: dir)
    end
  end

  it "says what to do when no release has been imported" do
    get "/agents/install"
    expect(response).to have_http_status(:ok)
    expect(page.at_css("#no_release").text).to include("Import a signed release on the Agents page first")
    expect(page.css(".token")).to be_empty
  end

  it "shows the commands for the current release, whose download passes the check command shown" do
    import_release(signed_release(version: "1.1.0"), operator:)
    current = import_release(release = signed_release(version: "1.2.0"), operator:)
    import_release(signed_release(version: "1.3.0-rc.1"), operator:) # pre-releases are not offered by default

    get "/agents/install"
    expect(page.at_css("#release_version").text).to eq("1.2.0")
    expect(command("download_command")).to eq("curl -fL -o fleet-agent https://agent.fleet.example.lan/api/v1/releases/1.2.0/binary")
    expect(command("check_command")).to eq(%(echo "#{current.sha256}  fleet-agent" | sha256sum -c))
    expect(command("release_sha256")).to eq(current.sha256)
    expect(command("install_command")).to eq("chmod +x fleet-agent && sudo ./fleet-agent install --server https://agent.fleet.example.lan")
    expect(command("token_command")).to eq("chmod +x fleet-agent && sudo ./fleet-agent install --server https://agent.fleet.example.lan --token-stdin")

    check = command("check_command")
    downloaded = fetch_download(command("download_command"))
    expect(downloaded).to eq(release.binary)
    output, status = run_check(check, downloaded)
    expect(status).to be_success
    expect(output).to eq("fleet-agent: OK\n")
    _output, status = run_check(check, signed_release(version: "1.1.0").binary)
    expect(status).not_to be_success # another binary fails the check
  end

  it "shows the checksum of exactly the release it links to, for any imported release" do
    releases = %w[1.1.0 1.2.0 1.3.0-rc.1].map { |version| import_release(signed_release(version:), operator:) }
    releases.each do |release|
      get "/agents/install", params: { version: release.version }
      expect(page.at_css("#release_version").text).to eq(release.version)
      cloud_init = YAML.safe_load(command("cloud_init"))
      [ command("download_command"), cloud_init["runcmd"][0] ].each do |download|
        expect(download).to end_with("/api/v1/releases/#{release.version}/binary")
      end
      [ command("check_command"), cloud_init["runcmd"][1] ].each do |check|
        expect(check).to include(release.sha256)
        expect(check.scan(/\h{64}/)).to eq([ release.sha256 ])
      end
      expect(page.text.scan(/\b\h{64}\b/).uniq).to eq([ release.sha256 ]) # no other release's checksum anywhere
      expect(page.text.include?("(a pre-release)")).to eq(release.prerelease?)
      check = command("check_command")
      output, status = run_check(check, fetch_download(command("download_command")))
      expect([ output, status.success? ]).to eq([ "fleet-agent: OK\n", true ])
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
    cloud_init = YAML.safe_load(command("cloud_init"))
    commands = [ command("install_command"), command("token_command"), *cloud_init["runcmd"] ]
    install_flags = commands.grep(/fleet-agent install/).flat_map { |line| line[/fleet-agent install (.*)/, 1].scan(/(?<=\s|\A)--[a-z-]+/) }
    expect(install_flags.uniq).to contain_exactly("--server", "--token-stdin", "--quiet")
    expect(install_flags - known).to eq([])
    expect(agent_install_source).to include('std::env::var("FLEET_ENROLLMENT_TOKEN")')
    expect(cloud_init["runcmd"].last).to eq("FLEET_ENROLLMENT_TOKEN='<one-time token>' /root/fleet-agent install --server https://agent.fleet.example.lan --quiet")
    expect(cloud_init["runcmd"][2]).to eq("chmod +x /root/fleet-agent")
    expect(command("cloud_init")).to start_with("#cloud-config\n")
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

  it "adds the download and check to a pre-registered host's one-time token page" do
    current = import_release(signed_release(version: "1.2.0"), operator:)
    post "/hosts", params: { host: { name: "Lab sandbox", hostname: "vm-06.example.lan" } }
    tokens = page.css(".token").map(&:text)
    expect(tokens).to include("curl -fL -o fleet-agent https://agent.fleet.example.lan/api/v1/releases/1.2.0/binary",
                              %(echo "#{current.sha256}  fleet-agent" | sha256sum -c))
  end

  it "links a pre-registered host's token page to this page while no release is imported" do
    post "/hosts", params: { host: { name: "Lab sandbox", hostname: "vm-06.example.lan" } }
    expect(page.at_css("a[href='/agents/install']").text).to eq("Install an agent")
  end
end
