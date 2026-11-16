# The server's own TLS certificate (ADR 0024), for the Settings page's expiry; Puma serves it (config/puma.rb).
# Read again here so a broken certificate also stops `bin/rails` commands, not only the server.
#
# server_tls_root_file: the file name, in agent/trust, of the certificate authority among the agent's compiled-in
# roots (FLEET_AGENT_TRUST_DIR, the same files) that signed it. The install commands fetch that file from the
# repository on GitHub and give it to curl, which only knows the system store, to download the agent (#181). nil for
# a publicly trusted certificate, or with no certificate.
require Rails.root.join("lib/tls/server_tls").to_s

Rails.application.configure do
  tls = ServerTls.from_env
  config.x.server_tls = tls
  trust_dir = Pathname(ENV.fetch("FLEET_AGENT_TRUST_DIR", Rails.root.join("../agent/trust").to_s))
  roots = trust_dir.glob("*.pem").sort.to_h { |path| [ path.read, path.basename.to_s ] }
  config.x.server_tls_root_file = roots[tls&.issuing_root(roots.keys)]
end
