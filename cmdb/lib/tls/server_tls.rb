require "base64"
require "openssl"

# The server's own TLS certificate (ADR 0024): a Cloudflare Origin CA certificate for the agent hostname, which
# the tunnel also connects to. Read from FLEET_TLS_CERT_BASE64 and FLEET_TLS_KEY_BASE64 (each the PEM file,
# base64-encoded onto one line, because docker's --env-file takes one line per value); the deploy workflow
# encodes them from its secrets. Both unset: no TLS listener (development, tests, or a server behind its own
# proxy). One set without the other, a value that is not base64 of a PEM certificate or key, a key that does not
# belong to the certificate, or a certificate that does not cover FLEET_AGENT_HOST stops the server at boot,
# naming the setting, so a broken certificate never reaches agents.
#
# Plain Ruby, loaded by config/puma.rb before the application, and by config/initializers/server_tls.rb. Never
# logs or prints the key.
class ServerTls
  class Error < StandardError; end

  CERT = "FLEET_TLS_CERT_BASE64".freeze
  KEY = "FLEET_TLS_KEY_BASE64".freeze
  PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m

  attr_reader :cert_pem, :key_pem, :certificate

  # nil when neither setting is set.
  def self.from_env(env = ENV)
    cert, key = env[CERT].to_s.strip, env[KEY].to_s.strip
    return nil if cert.empty? && key.empty?
    raise Error, "set both #{CERT} and #{KEY}, or neither" if cert.empty? || key.empty?

    tls = new(decode(cert, CERT), decode(key, KEY))
    agent_host = env["FLEET_AGENT_HOST"].to_s.strip.downcase
    if !agent_host.empty? && !tls.covers?(agent_host)
      raise Error, "#{CERT} is for #{tls.names.join(', ').then { |n| n.empty? ? 'no hostname' : n }}, not FLEET_AGENT_HOST (#{agent_host})"
    end
    tls
  end

  def self.decode(value, name)
    Base64.strict_decode64(value.delete("\n\r "))
  rescue ArgumentError
    raise Error, "#{name} is not base64 (encode the PEM file with base64 -w0)"
  end

  def initialize(cert_pem, key_pem)
    pems = cert_pem.scan(PEM_CERTIFICATE)
    raise Error, "#{CERT} holds no PEM certificate (-----BEGIN CERTIFICATE-----)" if pems.empty?

    @certificate = OpenSSL::X509::Certificate.new(pems.first)
    begin
      key = OpenSSL::PKey.read(key_pem)
    rescue OpenSSL::PKey::PKeyError
      raise Error, "#{KEY} is not a PEM private key"
    end
    raise Error, "#{KEY} is not the private key of the certificate in #{CERT}" unless key.private? && @certificate.check_private_key(key)

    @cert_pem = pems.join("\n") + "\n"
    @key_pem = key_pem
  rescue OpenSSL::X509::CertificateError
    raise Error, "#{CERT} holds a certificate that cannot be read"
  end

  # The DNS names in the certificate's subjectAltName.
  def names
    san = certificate.extensions.find { |e| e.oid == "subjectAltName" }
    san ? san.value.split(",").map(&:strip).filter_map { |n| n.delete_prefix("DNS:") if n.start_with?("DNS:") } : []
  end

  def covers?(hostname) = OpenSSL::SSL.verify_certificate_identity(certificate, hostname)

  def not_after = certificate.not_after

  def issuer = certificate.issuer.to_a.to_h { |name, value, _| [ name, value ] }.values_at("OU", "O", "CN").compact.first.to_s

  # The PEM of the certificate authority in pems (the agent's compiled-in roots, agent/trust) that signed this
  # certificate, directly or through the chain after it; nil when none did (a publicly trusted certificate).
  def issuing_root(pems)
    chain = cert_pem.scan(PEM_CERTIFICATE).map { |pem| OpenSSL::X509::Certificate.new(pem) }
    pems.find do |pem|
      root = OpenSSL::X509::Certificate.new(pem)
      store = OpenSSL::X509::Store.new
      store.add_cert(root)
      store.verify(certificate, chain.drop(1))
    rescue OpenSSL::X509::CertificateError, OpenSSL::X509::StoreError
      false
    end
  end

  # Never shows the key.
  def inspect = "#<ServerTls #{names.join(',')} until #{not_after.utc.iso8601}>"
end
