module Releases
  # Downloads a release's files from its GitHub release (P1-S15): the assets of the tag agent-v<version> in
  # FLEET_RELEASE_REPOSITORY, named as the release workflow names them (docs/releases.md). Plain HTTPS GETs of
  # the public download URLs, so no API token and no API rate limit; GitHub redirects them to its download
  # host. Nothing is trusted because of where it came from: Releases::Import verifies everything.
  class Github
    BASE = "https://github.com".freeze
    MAX_REDIRECTS = 5
    OPEN_TIMEOUT = 10
    READ_TIMEOUT = 30
    # The whole of one download, redirects included. READ_TIMEOUT bounds each read, not the transfer, so
    # without this a peer sending a byte every few seconds would hold a job worker indefinitely (review of
    # #74). 64 MiB in 5 minutes needs about 220 KB/s.
    DEADLINE = 300
    REDIRECTS = [ 301, 302, 303, 307, 308 ].freeze

    # The release or one of its files does not exist. Retrying will not help.
    class NotFound < StandardError; end

    # GitHub could not be reached or failed. The job retries this with backoff.
    class Unavailable < StandardError; end

    def initialize(version, repository: Releases.config.github_repository)
      @version = version
      @repository = repository
    end

    def tag = "agent-v#{@version}"

    def url(asset) = "#{BASE}/#{@repository}/releases/download/#{tag}/#{asset}"

    def manifest = fetch(url("#{Releases.binary_name(@version)}.manifest.json"), limit: MAX_MANIFEST_BYTES)

    def signature = fetch(url("#{Releases.binary_name(@version)}.manifest.json.minisig"), limit: MAX_SIGNATURE_BYTES)

    # Streams the binary into io, at most limit bytes.
    def binary(io, limit:) = fetch(url(Releases.binary_name(@version)), limit:, into: io)

    private

    # GETs url, following redirects to other HTTPS URLs. Returns the body as a binary String, or writes it to
    # into. A body longer than limit is cut at limit + 1 bytes, so the caller's size check fails clearly.
    def fetch(url, limit:, into: nil, redirects: MAX_REDIRECTS, deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + DEADLINE)
      uri = URI.parse(url)
      raise Unavailable, "GitHub redirected to a URL that is not HTTPS" unless uri.is_a?(URI::HTTPS)

      Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT) do |http|
        http.request(Net::HTTP::Get.new(uri, "User-Agent" => "fleet-cmdb release import", "Accept" => "application/octet-stream")) do |response|
          case response.code.to_i
          when 200 then return read(response, limit, into, deadline)
          when *REDIRECTS
            raise Unavailable, "GitHub redirected too many times" if redirects.zero?

            location = response["location"] or raise Unavailable, "GitHub sent a redirect without a location"
            return fetch(URI.join(url, location).to_s, limit:, into:, redirects: redirects - 1, deadline:)
          when 404 then raise NotFound, "GitHub has no release #{tag} in #{@repository} with the file #{File.basename(URI.parse(url).path)}"
          else raise Unavailable, "GitHub answered HTTP #{response.code}"
          end
        end
      end
    rescue URI::Error
      raise Unavailable, "GitHub redirected to an invalid URL"
    rescue Timeout::Error, SocketError, SystemCallError, OpenSSL::SSL::SSLError, IOError, Net::HTTPBadResponse, Net::ProtocolError => e
      raise Unavailable, "could not download from GitHub (#{e.class.name.demodulize})"
    end

    def read(response, limit, into, deadline)
      body = into ? nil : +"".b
      read = 0
      response.read_body do |chunk|
        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          raise Unavailable, "the download from GitHub took longer than #{DEADLINE} seconds"
        end

        chunk = chunk.byteslice(0, limit + 1 - read)
        read += chunk.bytesize
        into ? into.write(chunk) : body << chunk
        break if read > limit
      end
      body
    end
  end
end
