module FleetSimulator
  # Timings and outcomes of every request the simulator makes. Thread-safe: the runner's workers record into it.
  class Stats
    Sample = Data.define(:kind, :host, :status, :ms, :at, :note)

    def initialize
      @samples = []
      @lock = Mutex.new
    end

    def record(kind:, host:, status:, ms:, at:, note: nil)
      sample = Sample.new(kind: kind.to_s, host:, status:, ms: ms.round(2), at:, note:)
      @lock.synchronize { @samples << sample }
      sample
    end

    def samples = @lock.synchronize { @samples.dup }

    def of(kind) = samples.select { |s| s.kind == kind.to_s }

    # Nearest-rank percentile of a list of numbers (nil when empty).
    def self.percentile(values, pct)
      return nil if values.empty?

      sorted = values.sort
      sorted[[ (pct / 100.0 * sorted.size).ceil - 1, 0 ].max]
    end

    # Count, error count, and p50/p95/p99/max in milliseconds for one kind, or for a subset of its samples.
    def summary(kind, subset = of(kind))
      times = subset.map(&:ms)
      { count: subset.size, errors: subset.count { |s| !s.status.to_i.between?(200, 299) },
        p50: self.class.percentile(times, 50), p95: self.class.percentile(times, 95),
        p99: self.class.percentile(times, 99), max: times.max }
    end

    # The summary over the first and the last quarter of the run, to show whether a kind degrades over time.
    def quarters(kind)
      list = of(kind).sort_by(&:at)
      size = (list.size / 4.0).ceil
      { first: summary(kind, list.first(size)), last: summary(kind, list.last(size)) }
    end

    def status_counts(kind) = of(kind).group_by(&:status).transform_values(&:size).sort_by { |status, _| status.to_s }.to_h

    # Raw samples as CSV, for the delivery note.
    def to_csv
      rows = samples.sort_by(&:at).map { |s| [ s.at.utc.iso8601(3), s.kind, s.host, s.status, s.ms, s.note ] }
      ([ %w[at kind host status ms note] ] + rows).map { |row| row.map { |field| self.class.csv_field(field) }.join(",") }.join("\n") << "\n"
    end

    # RFC 4180: a field with a comma, quote, or line break is quoted, with its quotes doubled.
    def self.csv_field(value)
      text = value.to_s
      text.match?(/[",\r\n]/) ? %("#{text.gsub('"', '""')}") : text
    end
  end
end
