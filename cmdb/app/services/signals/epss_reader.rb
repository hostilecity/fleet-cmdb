require "zlib"

module Signals
  # Reads FIRST's daily EPSS file (VT-S03) one row at a time, in bounded memory: a gzip CSV (or the same CSV
  # uncompressed, for an offline import) whose first line is a comment with the model version and score date,
  #
  #   #model_version:v2025.03.14,score_date:2026-11-19T12:55:00Z
  #   cve,epss,percentile
  #   CVE-1999-0001,0.01141,0.77939
  #
  # Limits: MAX_COMPRESSED_BYTES on disk, MAX_UNCOMPRESSED_BYTES once inflated, MAX_ROWS rows, and MAX_LINE_BYTES a
  # line. A row with a malformed CVE id or a number outside 0 to 1 is skipped and counted (the first PROBLEM_LIMIT
  # with their line). A file without the comment or the header, a broken gzip stream, or a limit passed raises
  # Advisories::Unreadable, and nothing is imported.
  #
  # The work is bounded, not only the bytes (review of #269): the file is inflated in CHUNK-sized reads and split into
  # lines here (Zlib::GzipReader#gets slows down sharply on very compressible input: 4 MiB of newlines took 96 s), every
  # line counts toward MAX_ROWS, blank or not, and reading stops with Unreadable past DEADLINE seconds. A score date more
  # than a day ahead of the server's clock (UTC) is refused, since it would make every later file look older.
  class EpssReader
    MAX_COMPRESSED_BYTES = 64.megabytes
    MAX_UNCOMPRESSED_BYTES = 512.megabytes
    MAX_ROWS = 2_000_000
    MAX_LINE_BYTES = 4.kilobytes
    CHUNK = 64.kilobytes
    DEADLINE = 600
    PROBLEM_LIMIT = 100
    # Digits after the decimal point a score or percentile may have once written out (EPSS publishes 5), so a value is
    # stored exactly and an absurdly long number is refused (epss_scores.score is numeric(11, 10)).
    MAX_DECIMALS = 10
    HEADER = "cve,epss,percentile".freeze
    MODEL_VERSION = /\A[0-9A-Za-z][0-9A-Za-z._-]{0,63}\z/
    NUMBER = /\A(?:\d{1,3}(?:\.\d{1,20})?|\.\d{1,20})(?:[eE][-+]?\d{1,2})?\z/
    GZIP_MAGIC = "\x1f\x8b".b
    NEWLINE = /\n/

    attr_reader :model_version, :score_date, :rows, :malformed, :problems

    def initialize(path, name: nil)
      @path = Pathname(path)
      @name = Advisories::Record.clean_text(name || @path.basename.to_s, 200) || "file"
    end

    # Reads the comment and the header, then yields [cve_id, score, percentile] per valid row, the numbers as decimal
    # strings. model_version and score_date are set before the first row is yielded.
    def each
      raise unreadable("is not a file") unless @path.file?
      raise unreadable("is larger than #{MAX_COMPRESSED_BYTES / 1.megabyte} MiB") if @path.size > MAX_COMPRESSED_BYTES

      @rows = 0
      @malformed = 0
      @problems = []
      @bytes = 0
      @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + DEADLINE
      @path.open("rb") do |file|
        gzip = file.read(2) == GZIP_MAGIC
        file.rewind
        @io = gzip ? Zlib::GzipReader.new(file) : file
        @scanner = StringScanner.new(+"".b)
        @eof = false
        read_preamble
        line_number = 2
        while (line = next_line)
          line_number += 1
          @rows += 1
          raise unreadable("has more than #{MAX_ROWS.to_fs(:delimited)} rows") if @rows > MAX_ROWS
          next if line.strip.empty?

          row = parse_row(line, line_number)
          yield row if row
        end
      end
    rescue Zlib::Error
      raise unreadable("is not a valid gzip file")
    end

    private

    # The next line without its newline, or nil at the end. Reads CHUNK bytes at a time; a line longer than
    # MAX_LINE_BYTES, more than MAX_UNCOMPRESSED_BYTES in all, or reading past DEADLINE raises Unreadable.
    def next_line
      loop do
        if (line = @scanner.scan_until(NEWLINE))
          raise unreadable("has a line longer than #{MAX_LINE_BYTES} bytes") if line.bytesize > MAX_LINE_BYTES

          return text(line.chomp)
        end
        rest = @scanner.rest
        raise unreadable("has a line longer than #{MAX_LINE_BYTES} bytes") if rest.bytesize > MAX_LINE_BYTES
        return (rest.empty? ? nil : text(rest).tap { @scanner.terminate }) if @eof

        fill(rest)
      end
    end

    def fill(rest)
      raise unreadable("took longer than #{DEADLINE} seconds to read") if Process.clock_gettime(Process::CLOCK_MONOTONIC) > @deadline

      chunk = @io.read(CHUNK)
      if chunk.nil?
        @eof = true
        @scanner = StringScanner.new(rest)
        return
      end
      @bytes += chunk.bytesize
      raise unreadable("is larger than #{MAX_UNCOMPRESSED_BYTES / 1.megabyte} MiB uncompressed") if @bytes > MAX_UNCOMPRESSED_BYTES

      @scanner = StringScanner.new(rest << chunk)
    end

    def text(bytes) = bytes.force_encoding(Encoding::UTF_8).scrub("?")

    # "#model_version:v2025.03.14,score_date:2026-11-19T12:55:00Z", then the header.
    def read_preamble
      comment = next_line.to_s
      fields = comment.delete_prefix("#").split(",").to_h { |pair| pair.split(":", 2).map(&:strip) } if comment.start_with?("#")
      version = fields&.fetch("model_version", nil)
      date = fields&.fetch("score_date", nil).to_s[0, 10]
      unless version&.match?(MODEL_VERSION) && date.match?(/\A\d{4}-\d\d-\d\d\z/)
        raise unreadable("does not start with EPSS's model version and score date (#model_version:...,score_date:...)")
      end

      @model_version = version
      @score_date = Date.iso8601(date)
      if @score_date > Time.now.utc.to_date + 1
        raise unreadable("has a score date of #{@score_date.iso8601}, more than a day ahead of this server's clock")
      end
      raise unreadable("has no cve,epss,percentile header on its second line") unless next_line.to_s.strip == HEADER
    rescue Date::Error
      raise unreadable("has a score date that is not a date")
    end

    def parse_row(line, line_number)
      cve_id, score, percentile, extra = line.split(",", 4).map(&:strip)
      problem = if extra || percentile.nil? then "does not have three fields"
      elsif !cve_id.match?(CVE) then "has no valid CVE id"
      elsif !share?(score) then "has an EPSS score that is not a number from 0 to 1 with at most #{MAX_DECIMALS} decimals"
      elsif !share?(percentile) then "has a percentile that is not a number from 0 to 1 with at most #{MAX_DECIMALS} decimals"
      end
      return [ cve_id, decimal(score), decimal(percentile) ] unless problem

      @malformed += 1
      @problems << { "line" => line_number, "problem" => problem } if @problems.size < PROBLEM_LIMIT
      nil
    end

    def share?(value)
      return false unless value.match?(NUMBER)

      number = BigDecimal(value)
      number.between?(0, 1) && number.round(MAX_DECIMALS) == number
    end

    def decimal(value) = BigDecimal(value).to_s("F")

    def unreadable(problem) = Advisories::Unreadable.new("#{@name} #{problem}, so nothing was imported")
  end
end
