require "rails_helper"

# The server's own TLS certificate from FLEET_TLS_CERT_BASE64 and FLEET_TLS_KEY_BASE64 (ADR 0024). A broken
# certificate stops the server at boot with a message naming the setting, so it never reaches agents.
RSpec.describe ServerTls do
  def key = OpenSSL::PKey::EC.generate("prime256v1")

  def certificate(key, names: [ "agent.fleet.example.lan" ], not_after: 1.year.from_now, issuer_key: key, issuer: "/CN=Test CA")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..2**32)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{names.first || 'none'}")
    cert.issuer = OpenSSL::X509::Name.parse(issuer)
    cert.public_key = key
    cert.not_before = 1.hour.ago
    cert.not_after = not_after
    extensions = OpenSSL::X509::ExtensionFactory.new
    extensions.subject_certificate = cert
    cert.add_extension(extensions.create_extension("subjectAltName", names.map { |n| "DNS:#{n}" }.join(","))) if names.any?
    cert.sign(issuer_key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def env(cert_pem, key_pem, agent_host: "agent.fleet.example.lan")
    { "FLEET_TLS_CERT_BASE64" => Base64.strict_encode64(cert_pem), "FLEET_TLS_KEY_BASE64" => Base64.strict_encode64(key_pem), "FLEET_AGENT_HOST" => agent_host }
  end

  let(:server_key) { key }
  let(:server_cert) { certificate(server_key, issuer_key: key) }

  it "is nil when neither setting is set" do
    expect(described_class.from_env({})).to be_nil
    expect(described_class.from_env("FLEET_TLS_CERT_BASE64" => " ", "FLEET_TLS_KEY_BASE64" => "")).to be_nil
  end

  it "reads the certificate and key, and says what they cover and when they expire, never showing the key" do
    tls = described_class.from_env(env(server_cert.to_pem, server_key.to_pem))
    expect(tls.names).to eq([ "agent.fleet.example.lan" ])
    expect(tls.issuer).to eq("Test CA")
    expect(tls.not_after).to be_within(1).of(server_cert.not_after)
    expect(tls.covers?("agent.fleet.example.lan")).to be(true)
    expect(tls.cert_pem).to eq(server_cert.to_pem)
    expect(tls.inspect).not_to include("PRIVATE")
  end

  it "keeps a chain after the certificate, and takes base64 with line breaks" do
    chain = server_cert.to_pem + certificate(key).to_pem
    tls = described_class.from_env(env(chain, server_key.to_pem).transform_values { |v| v.scan(/.{1,64}/).join("\n") })
    expect(tls.cert_pem.scan("BEGIN CERTIFICATE").size).to eq(2)
  end

  {
    "only the certificate" => ->(e) { e.except("FLEET_TLS_KEY_BASE64") },
    "only the key" => ->(e) { e.except("FLEET_TLS_CERT_BASE64") }
  }.each do |label, change|
    it "stops when given #{label}" do
      expect { described_class.from_env(change.(env(server_cert.to_pem, server_key.to_pem))) }
        .to raise_error(ServerTls::Error, "set both FLEET_TLS_CERT_BASE64 and FLEET_TLS_KEY_BASE64, or neither")
    end
  end

  it "stops, naming the setting, for values that are not base64 of a PEM certificate and its key" do
    good = env(server_cert.to_pem, server_key.to_pem)
    {
      good.merge("FLEET_TLS_CERT_BASE64" => "not base64!") => "FLEET_TLS_CERT_BASE64 is not base64 (encode the PEM file with base64 -w0)",
      good.merge("FLEET_TLS_CERT_BASE64" => Base64.strict_encode64("hello")) => "FLEET_TLS_CERT_BASE64 holds no PEM certificate (-----BEGIN CERTIFICATE-----)",
      good.merge("FLEET_TLS_CERT_BASE64" => Base64.strict_encode64("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")) =>
        "FLEET_TLS_CERT_BASE64 holds a certificate that cannot be read",
      good.merge("FLEET_TLS_KEY_BASE64" => Base64.strict_encode64("hello")) => "FLEET_TLS_KEY_BASE64 is not a PEM private key",
      env(server_cert.to_pem, key.to_pem) => "FLEET_TLS_KEY_BASE64 is not the private key of the certificate in FLEET_TLS_CERT_BASE64"
    }.each do |values, message|
      expect { described_class.from_env(values) }.to raise_error(ServerTls::Error, message)
    end
  end

  it "finds the certificate authority that signed it among the agent's roots, and none for another authority" do
    ca_key = key
    ca = certificate(ca_key, names: [], issuer: "/CN=Test Origin CA")
    ca.subject = OpenSSL::X509::Name.parse("/CN=Test Origin CA")
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = factory.issuer_certificate = ca
    ca.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    ca.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    ca.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    leaf = certificate(server_key, issuer_key: ca_key, issuer: "/CN=Test Origin CA")
    tls = described_class.from_env(env(leaf.to_pem, server_key.to_pem))
    cloudflare = Rails.root.join("../agent/trust").glob("*.pem").sort.map(&:read)
    expect(tls.issuing_root([ *cloudflare, ca.to_pem ])).to eq(ca.to_pem)
    expect(tls.issuing_root(cloudflare)).to be_nil
    expect(tls.issuing_root([ "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", ca.to_pem ])).to eq(ca.to_pem) # an unreadable file is skipped
    expect(described_class.from_env(env(server_cert.to_pem, server_key.to_pem)).issuing_root([ ca.to_pem ])).to be_nil
  end

  it "stops when the certificate does not cover FLEET_AGENT_HOST, the name agents and the tunnel connect to" do
    expect { described_class.from_env(env(server_cert.to_pem, server_key.to_pem, agent_host: "fleet-vm.example.lan")) }
      .to raise_error(ServerTls::Error, "FLEET_TLS_CERT_BASE64 is for agent.fleet.example.lan, not FLEET_AGENT_HOST (fleet-vm.example.lan)")
    wildcard_key = key
    wildcard = certificate(wildcard_key, names: [ "*.example.lan" ])
    expect(described_class.from_env(env(wildcard.to_pem, wildcard_key.to_pem, agent_host: "fleet-vm.example.lan")).covers?("fleet-vm.example.lan")).to be(true)
  end
end
