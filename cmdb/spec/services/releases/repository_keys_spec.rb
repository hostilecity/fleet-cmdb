require "rails_helper"

# The repository's release public keys (agent/release-keys, #181): the install page compares this server's keys with
# them, and the docs print them so a person can compare by hand. A key rotation changes the files, and this spec then
# fails until the docs show the new keys too.
RSpec.describe "Releases.repository_keys" do
  let(:real_dir) { Rails.root.join("../agent/release-keys").expand_path }

  def use_real_keys = (Rails.configuration.x.releases.repository_keys_dir = real_dir)

  it "reads the repository's real current and next keys" do
    use_real_keys
    keys = Releases.repository_keys
    expect(keys.keys).to eq(%w[current next])
    keys.each do |role, key|
      lines = real_dir.join("#{role}.pub").readlines(chomp: true)
      expect(key.line).to eq(lines.last)
      expect(lines.first).to eq("untrusted comment: minisign public key #{key.id_hex}")
    end
  end

  it "is printed, line for line, where the install docs tell people to compare it" do
    use_real_keys
    docs = %w[docs/releases.md docs/operations/install-agent.md].to_h { |path| [ path, Rails.root.join("..", path).read ] }
    Releases.repository_keys.compact.each_value do |key|
      docs.each { |path, text| expect(text).to include(key.line, key.id_hex), "#{path} lacks the #{key.role} key #{key.id_hex}" }
    end
  end

  it "treats a missing file, or one of comments only, as no key, and refuses one that is not a key" do
    publish_repository_keys(current: release_key, next_key: nil)
    expect(Releases.repository_keys.transform_values { |key| key&.line }).to eq("current" => release_key.public_line, "next" => nil)
    Rails.configuration.x.releases.repository_keys_dir.join("next.pub").delete
    expect(Releases.repository_keys["next"]).to be_nil
    Rails.configuration.x.releases.repository_keys_dir.join("current.pub").write("not a key\n")
    expect { Releases.repository_keys }.to raise_error(Releases::KeyError, /current release key/)
  end

  it "names the configured keys that differ from the repository's" do
    trust_release_keys(current: release_key, next_key: next_release_key)
    expect(Releases.keys_unlike_repository).to eq([])
    publish_repository_keys(current: release_key, next_key: nil)
    expect(Releases.keys_unlike_repository).to eq(%w[next])
    publish_repository_keys(current: next_release_key, next_key: release_key)
    expect(Releases.keys_unlike_repository).to eq(%w[current next])
  end

  it "fetches the install check's key from the release's own tag on GitHub, never from this server" do
    expect(Releases.public_key_url("1.3.0-rc.1")).to eq("https://raw.githubusercontent.com/hostilecity/fleet-cmdb/refs/tags/agent-v1.3.0-rc.1/agent/release-keys/current.pub")
    expect(Releases.source_url("1.2.0", "agent/trust/cloudflare-origin-rsa.pem")).to eq("https://raw.githubusercontent.com/hostilecity/fleet-cmdb/refs/tags/agent-v1.2.0/agent/trust/cloudflare-origin-rsa.pem")
  end
end
