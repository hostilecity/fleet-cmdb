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
  class EpssReader
    MAX_COMPRESSED_BYTES = 64.megabytes
    MAX_UNCOMPRESSED_BYTES = 512.megabytes
    MAX_ROWS = 2_000_000
    MAX_LINE_BYTES = 4.kilobytes
    PROBLEM_LIMIT = 100
    HEADER = "cve,epss,percentile".freeze
    MODEL_VERSION = /\A[0-9A-Za-z][0-9A-Za-z._-]{0,63}\z/
    NUMBER = /\A(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][-+]?\d{1,3})?\z/
    GZIP_MAGIC = "\x1f\x8b".b

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
      @path.open("rb") do |file|
        io = file.read(2) == GZIP_MAGIC ? Zlib::GzipReader.new(file.tap(&:rewind)) : file.tap(&:rewind)
        read_preamble(io)
        line_number = 2
        while (line = next_line(io))
          line_number += 1
          next if line.strip.empty?

          @rows += 1
          raise unreadable("has more than #{MAX_ROWS.to_fs(:delimited)} rows") if @rows > MAX_ROWS

          row = parse_row(line, line_number)
          yield row if row
        end
      end
    rescue Zlib::Error
      raise unreadable("is not a valid gzip file")
    end

    private

    def next_line(io)
      line = io.gets("\n", MAX_LINE_BYTES)
      return nil if line.nil?

      @bytes += line.bytesize
      raise unreadable("is larger than #{MAX_UNCOMPRESSED_BYTES / 1.megabyte} MiB uncompressed") if @bytes > MAX_UNCOMPRESSED_BYTES
      raise unreadable("has a line longer than #{MAX_LINE_BYTES} bytes") if line.bytesize >= MAX_LINE_BYTES && !line.end_with?("\n")

      line.force_encoding(Encoding::UTF_8).scrub("?").chomp
    end

    # "#model_version:v2025.03.14,score_date:2026-11-19T12:55:00Z", then the header.
    def read_preamble(io)
      comment = next_line(io).to_s
      fields = comment.delete_prefix("#").split(",").to_h { |pair| pair.split(":", 2).map(&:strip) } if comment.start_with?("#")
      version = fields&.fetch("model_version", nil)
      date = fields&.fetch("score_date", nil).to_s[0, 10]
      unless version&.match?(MODEL_VERSION) && date.match?(/\A\d{4}-\d\d-\d\d\z/)
        raise unreadable("does not start with EPSS's model version and score date (#model_version:...,score_date:...)")
      end

      @model_version = version
      @score_date = Date.iso8601(date)
      raise unreadable("has no cve,epss,percentile header on its second line") unless next_line(io).to_s.strip == HEADER
    rescue Date::Error
      raise unreadable("has a score date that is not a date")
    end

    def parse_row(line, line_number)
      cve_id, score, percentile, extra = line.split(",", 4).map(&:strip)
      problem = if extra || percentile.nil? then "does not have three fields"
      elsif !cve_id.match?(CVE) then "has no valid CVE id"
      elsif !share?(score) then "has an EPSS score that is not a number from 0 to 1"
      elsif !share?(percentile) then "has a percentile that is not a number from 0 to 1"
      end
      return [ cve_id, decimal(score), decimal(percentile) ] unless problem

      @malformed += 1
      @problems << { "line" => line_number, "problem" => problem } if @problems.size < PROBLEM_LIMIT
      nil
    end

    def share?(value) = value.match?(NUMBER) && BigDecimal(value).between?(0, 1)

    def decimal(value) = BigDecimal(value).to_s("F")

    def unreadable(problem) = Advisories::Unreadable.new("#{@name} #{problem}, so nothing was imported")
  end
end
