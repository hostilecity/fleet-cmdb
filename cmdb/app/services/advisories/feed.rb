module Advisories
  # Downloads the configured advisory archive (P2-S13, DEC-11), or the Debian Security Tracker's document
  # (P2-S16, DEC-22, with label, accept, and suffix of its own), into a temporary file: HTTPS only, with the
  # certificate verified, at most max_bytes, within DEADLINE, and conditionally (If-None-Match and
  # If-Modified-Since from the last successful download), so an unchanged archive is not downloaded again.
  #
  # Nothing secret reaches a log or an error: messages name only the feed's host, never its path, query, or
  # the token (NFR-1). The token, when configured, is sent as a bearer credential.
  class Feed
    OPEN_TIMEOUT = 15
    READ_TIMEOUT = 60
    # The whole exchange, connection, headers, redirects, and body included: READ_TIMEOUT bounds each read, so a
    # server trickling bytes could otherwise hold a worker indefinitely. Enforced with Timeout around the whole
    # fetch, since a slow status line or headers never reach a body callback (review of #103). 512 MiB in 15 minutes needs about 600 KB/s.
    DEADLINE = 900
    MAX_REDIRECTS = 3
    REDIRECTS = [ 301, 302, 303, 307, 308 ].freeze

    # The download failed. The refresh job retries it with backoff, then reports it.
    class Unavailable < StandardError; end

    # Raised by Timeout inside the exchange; not a Timeout::Error, so get's network rescue leaves it to fetch.
    class DeadlineExceeded < StandardError; end

    # file: a Tempfile holding the archive (nil when not modified). Close it with close!.
    Download = Data.define(:file, :etag, :last_modified) do
      def not_modified? = file.nil?
      def close! = file&.close!
    end

    attr_reader :url

    # label: what messages call the source ("advisory feed"). accept: the Accept header. suffix: the temporary
    # file's extension, which the reader may go by.
    def initialize(url: Advisories.config.feed_url, token: Advisories.config.feed_token, max_bytes: Advisories.config.max_download_bytes,
                   label: "advisory feed", accept: "application/zip, application/octet-stream", suffix: ".zip")
      @url = url
      @token = token
      @max_bytes = max_bytes
      @label = label
      @accept = accept
      @suffix = suffix
    end

    # What imports record as their source: the host and path, never a query string (it could carry a key).
    def source
      uri = URI.parse(@url)
      "#{uri.host}#{uri.path}"
    end

    def fetch(etag: nil, last_modified: nil)
      file = Tempfile.new([ "advisories-", @suffix ], binmode: true)
      headers = { "User-Agent" => "fleet-cmdb advisory refresh", "Accept" => @accept }
      headers["If-None-Match"] = etag if etag
      headers["If-Modified-Since"] = last_modified if last_modified
      headers["Authorization"] = "Bearer #{@token}" if @token
      download = Timeout.timeout(DEADLINE, DeadlineExceeded) { get(@url, headers, file, MAX_REDIRECTS) }
      file.close! if download.not_modified?
      download
    rescue DeadlineExceeded
      file&.close!
      raise Unavailable, deadline_message
    rescue StandardError
      file&.close!
      raise
    end

    private

    def host = URI.parse(@url).host

    def deadline_message = "the download from the #{@label} at #{host} took longer than #{DEADLINE} seconds"

    def get(url, headers, file, redirects)
      uri = URI.parse(url)
      raise Unavailable, "the #{@label} at #{host} redirected to a URL that is not HTTPS" unless uri.is_a?(URI::HTTPS)

      Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_PEER,
                                          open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT) do |http|
        http.request(Net::HTTP::Get.new(uri, headers)) do |response|
          case response.code.to_i
          when 200
            read(response, file)
            return Download.new(file:, etag: response["etag"]&.first(256), last_modified: response["last-modified"]&.first(64))
          when 304
            raise Unavailable, "the #{@label} at #{host} answered 304 to a request that was not conditional" unless headers.key?("If-None-Match") || headers.key?("If-Modified-Since")

            return Download.new(file: nil, etag: headers["If-None-Match"], last_modified: headers["If-Modified-Since"])
          when *REDIRECTS
            raise Unavailable, "the #{@label} at #{host} redirected too many times" if redirects.zero?

            location = response["location"] or raise Unavailable, "the #{@label} at #{host} sent a redirect without a location"
            # The credential goes only to the configured host.
            target = URI.join(url, location)
            return get(target.to_s, target.host == host ? headers : headers.except("Authorization"), file, redirects - 1)
          else
            raise Unavailable, "the #{@label} at #{host} answered HTTP #{response.code.to_i}"
          end
        end
      end
    rescue URI::Error
      raise Unavailable, "the #{@label} at #{host} redirected to an invalid URL"
    rescue Timeout::Error, SocketError, SystemCallError, OpenSSL::SSL::SSLError, IOError, Net::HTTPBadResponse, Net::ProtocolError => e
      raise Unavailable, "could not download from the #{@label} at #{host} (#{e.class.name.demodulize})"
    end

    def read(response, file)
      file.truncate(0)
      file.rewind
      written = 0
      response.read_body do |chunk|
        written += chunk.bytesize
        raise Unavailable, "the #{@label} at #{host} sent more than #{@max_bytes / 1.megabyte} MiB" if written > @max_bytes

        file.write(chunk)
      end
      file.flush
    end
  end
end
