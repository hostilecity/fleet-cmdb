module Api
  module V1
    # Release downloads (P1-S16, ADR 0018): GET /api/v1/releases/<version>/manifest, /signature, and /binary.
    #
    # - On the agent hostname only (config/routes.rb and HostSeparation), like the rest of the agent API.
    # - Unauthenticated: releases are public and the installer has no credential yet. Limited per client
    #   address instead.
    # - Exempt from the minimum-version check (FR-S.5): an agent too old for the rest of the API must still be
    #   able to fetch the release that updates it. These requests carry no body and no agent version, and
    #   nothing here may start checking one.
    # - Served with a strong ETag (the file's SHA-256) and Content-Length. The binary also honours a single
    #   byte range (and If-Range), so an interrupted download resumes where it stopped.
    #
    # Agents verify what they download themselves; the URLs only say where to fetch it (location-independent,
    # ADR 0019).
    class ReleasesController < BaseController
      # A release never changes once published (docs/releases.md), so caches may keep it.
      CACHE_CONTROL = "public, max-age=86400".freeze
      CHUNK = 64.kilobytes

      rate_limit to: Releases.config.download_rate_limit[:to], within: Releases.config.download_rate_limit[:within],
                 by: -> { request.remote_ip }, store: AgentApi.rate_limit_store, name: "release_downloads", scope: "agent_api",
                 with: -> { rate_limited!(Releases.config.download_rate_limit[:within]) }

      before_action :find_release

      # GET /api/v1/releases/:version/manifest
      def manifest = send_bytes(@release.manifest, "application/json", @release.manifest_name)

      # GET /api/v1/releases/:version/signature
      def signature = send_bytes(@release.signature, "text/plain; charset=utf-8", @release.signature_name)

      # GET /api/v1/releases/:version/binary
      def binary
        path = @release.binary_path
        size = File.size?(path)
        unless size == @release.size
          logger.error("[releases] the stored binary for #{@release.version} is missing or has the wrong size: #{path}")
          raise AgentApi::InternalError
        end

        etag = %("#{@release.sha256}")
        set_download_headers(etag, @release.binary_name)
        response.set_header("Accept-Ranges", "bytes")
        return head(:not_modified) if not_modified?(etag)

        range = requested_range(size, etag)
        if range == :unsatisfiable
          response.set_header("Content-Range", "bytes */#{size}")
          return head(:range_not_satisfiable)
        end

        range ||= 0...size
        if range.size < size
          response.status = :partial_content
          response.set_header("Content-Range", "bytes #{range.begin}-#{range.end - 1}/#{size}")
        end
        response.set_header("Content-Type", "application/octet-stream")
        response.set_header("Content-Length", range.size.to_s)
        self.response_body = FileRange.new(path, range)
      end

      private

      def find_release
        version = params[:version].to_s
        @release = AgentRelease.find_by(version:) if Releases.valid_version?(version)
        raise AgentApi::NotFound.new("No such release.") unless @release
      end

      def send_bytes(bytes, content_type, filename)
        etag = %("#{OpenSSL::Digest::SHA256.hexdigest(bytes)}")
        set_download_headers(etag, filename)
        return head(:not_modified) if not_modified?(etag)

        response.set_header("Content-Length", bytes.bytesize.to_s)
        send_data bytes, type: content_type, disposition: "attachment", filename:
      end

      def set_download_headers(etag, filename)
        response.set_header("ETag", etag)
        response.set_header("Cache-Control", CACHE_CONTROL)
        response.set_header("Content-Disposition", ActionDispatch::Http::ContentDisposition.format(disposition: "attachment", filename:))
        response.set_header("X-Content-Type-Options", "nosniff")
      end

      # If-None-Match naming this ETag (or *): the client already has these bytes.
      def not_modified?(etag)
        header = request.headers["If-None-Match"].to_s
        header.strip == "*" || header.split(",").map { |tag| tag.strip.delete_prefix("W/") }.include?(etag)
      end

      # The single byte range asked for, as a Ruby range; nil for the whole file (no Range header, one this
      # does not serve such as several ranges, or an If-Range for other content); :unsatisfiable when the
      # range lies outside the file.
      def requested_range(size, etag)
        header = request.headers["Range"].presence or return nil
        if_range = request.headers["If-Range"].presence
        return nil if if_range && if_range != etag

        ranges = Rack::Utils.get_byte_ranges(header, size)
        return nil if ranges.nil? || ranges.size > 1
        return :unsatisfiable if ranges.empty?

        ranges.first.begin...(ranges.first.end + 1)
      end

      # Streams part of a file in chunks, without reading it all into memory.
      class FileRange
        def initialize(path, range)
          @path = path
          @range = range
        end

        def each
          File.open(@path, "rb") do |file|
            file.seek(@range.begin)
            left = @range.size
            while left.positive? && (chunk = file.read([ CHUNK, left ].min))
              left -= chunk.bytesize
              yield chunk
            end
          end
        end
      end
    end
  end
end
