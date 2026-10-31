require "rails_helper"

# P1-S16: release downloads on the agent hostname: unauthenticated but limited per address, with ETag,
# Content-Length, and resumable byte ranges, and exempt from the minimum agent version (FR-S.5).
RSpec.describe "Release downloads", type: :request do
  let(:release) { signed_release(version: "1.2.0", binary: SecureRandom.bytes(300_000)) }
  let(:stored) { import_release(release) }
  let(:path) { "/api/v1/releases/1.2.0" }

  before do
    trust_release_keys
    stored
  end

  def download(file, headers: {}, ip: "192.0.2.10", method: :get)
    public_send(method, "#{path}/#{file}", headers:, env: { "REMOTE_ADDR" => ip })
  end

  it "serves the manifest, signature, and binary exactly as verified, with ETag and Content-Length" do
    { "manifest" => [ release.manifest, "application/json", stored.manifest_name ],
      "signature" => [ release.signature, "text/plain; charset=utf-8", stored.signature_name ],
      "binary" => [ release.binary, "application/octet-stream", stored.binary_name ] }.each do |file, (body, type, name)|
      download(file)
      expect(response).to have_http_status(:ok), file
      expect(response.body.b).to eq(body.b)
      expect(response.headers).to include("Content-Type" => type, "Content-Length" => body.bytesize.to_s,
                                          "ETag" => %("#{OpenSSL::Digest::SHA256.hexdigest(body)}"), "Cache-Control" => "max-age=86400, public")
      expect(response.headers["Content-Disposition"]).to start_with(%(attachment; filename="#{name}"))
    end
    expect(response.headers).to include("ETag" => %("#{release.sha256}"), "Accept-Ranges" => "bytes")
  end

  it "answers a matching If-None-Match with 304 and no body" do
    %w[manifest signature binary].each do |file|
      download(file)
      etag = response.headers["ETag"]
      download(file, headers: { "If-None-Match" => %("other", #{etag}) })
      expect(response).to have_http_status(:not_modified), file
      expect(response.body).to be_empty
      expect(response.headers["ETag"]).to eq(etag)
      download(file, headers: { "If-None-Match" => %("other") })
      expect(response).to have_http_status(:ok)
    end
  end

  describe "resuming the binary" do
    it "gives a byte-identical binary when an interrupted download resumes" do
      cut = 123_457
      download("binary", headers: { "Range" => "bytes=0-#{cut - 1}" }) # the connection drops after this much
      first = response.body.b
      expect(response).to have_http_status(:partial_content)
      expect(response.headers).to include("Content-Range" => "bytes 0-#{cut - 1}/300000", "Content-Length" => cut.to_s)

      download("binary", headers: { "Range" => "bytes=#{cut}-", "If-Range" => %("#{release.sha256}") }) # curl -C -
      expect(response).to have_http_status(:partial_content)
      expect(response.headers).to include("Content-Range" => "bytes #{cut}-299999/300000", "Content-Length" => (300_000 - cut).to_s)
      resumed = first + response.body.b
      expect(resumed).to eq(release.binary)
      expect(OpenSSL::Digest::SHA256.hexdigest(resumed)).to eq(stored.sha256)
    end

    it "serves suffix ranges, and refuses a range past the end with 416" do
      download("binary", headers: { "Range" => "bytes=-10" })
      expect(response.body.b).to eq(release.binary[-10..])
      expect(response.headers["Content-Range"]).to eq("bytes 299990-299999/300000")
      download("binary", headers: { "Range" => "bytes=300000-" })
      expect(response).to have_http_status(:range_not_satisfiable)
      expect(response.headers["Content-Range"]).to eq("bytes */300000")
    end

    it "sends the whole binary for a stale If-Range, several ranges, or a malformed Range" do
      [ { "Range" => "bytes=10-", "If-Range" => %("not-this-release") }, { "Range" => "bytes=0-1,5-6" },
        { "Range" => "lines=1-2" }, { "Range" => "bytes=9-1" } ].each do |headers|
        download("binary", headers:)
        expect(response).to have_http_status(:ok), headers.inspect
        expect(response.body.b).to eq(release.binary)
      end
    end

    it "answers HEAD with the headers and no body" do
      download("binary", method: :head)
      expect(response).to have_http_status(:ok)
      expect(response.headers).to include("Content-Length" => "300000", "ETag" => %("#{release.sha256}"))
      expect(response.body).to be_empty
    end
  end

  it "answers 404 with the error envelope for an unknown or malformed version" do
    [ "/api/v1/releases/9.9.9/binary", "/api/v1/releases/1.2/manifest", "/api/v1/releases/..%2F..%2Fetc/binary",
      "/api/v1/releases/1.2.0+build/binary", "/api/v1/releases/1.2.0/other" ].each do |url|
      get url
      expect_error(:not_found, "not_found")
    end
  end

  it "answers 500 without serving anything if the stored binary is missing or changed size" do
    File.binwrite(stored.binary_path, "truncated")
    log = captured_log { download("binary") }
    expect_error(:internal_server_error, "internal_error")
    expect(log).to include("the stored binary for 1.2.0 is missing or has the wrong size")
  end

  it "is not served on the dashboard hostname" do
    host! dashboard_host
    %w[manifest signature binary].each do |file|
      download(file)
      expect(response).to have_http_status(:not_found)
      expect(response.body).to be_empty
    end
  end

  it "needs no credential and is served to agents below the minimum version (FR-S.5)" do
    allow(AgentApi.config).to receive(:minimum_agent_version).and_return("99.0.0")
    download("binary", headers: { "Authorization" => "Bearer not-a-credential", "User-Agent" => "fleet-agent/0.0.1" })
    expect(response).to have_http_status(:ok)
    expect(response.body.b).to eq(release.binary)
  end

  it "is rate-limited per client address" do
    limit = Releases.config.download_rate_limit[:to]
    limit.times { download("manifest") }
    expect(response).to have_http_status(:ok)
    download("binary", headers: { "Range" => "bytes=0-1" })
    expect_error(:too_many_requests, "rate_limited")
    expect(response.headers["Retry-After"]).to eq("60")
    download("manifest", ip: "192.0.2.11") # another address still can
    expect(response).to have_http_status(:ok)
  end
end
