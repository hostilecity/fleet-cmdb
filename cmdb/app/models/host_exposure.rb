# Why a host has its exposure points (VT-SCORES #262, VT-D04's score breakdown; mockup tiles.html#score), read for that
# host on its Vulnerabilities tab in one grouped query whatever its finding count: its open advisories, each in the
# worst bucket of its triaged findings with the KEV flag of any of them and the widest listener outside Ignorable, as
# host_compliance_counts counts them, then grouped into rows by bucket (known exploited apart; Fix available split
# into kernel steps and package upgrades), each with its advisories by severity and their points
# (VulnerabilityExposure::POINTS), and a row per listener kind for the points listening processes add. total is the
# summary's exposure_points for a scored host (a spec checks it).
class HostExposure
  Row = Data.define(:key, :label, :advisories, :severities, :points)

  WORST_SQL = <<~SQL.squish.freeze
    max(CASE WHEN vulnerability_findings.bucket = 2 THEN 5 WHEN vulnerability_findings.bucket = 1 THEN 4
             WHEN vulnerability_findings.bucket_rule = 9 THEN 3 WHEN vulnerability_findings.bucket = 3 THEN 2 ELSE 1 END)
  SQL
  KERNEL_SQL = "bool_or(vulnerability_findings.bucket = 1 AND vulnerability_findings.bucket_rule IN (3, 4))".freeze
  LISTENER_SQL = "max(vulnerability_findings.listener) FILTER (WHERE vulnerability_findings.bucket <> 4)".freeze
  WORST_LABELS = { 5 => "Needs attention", 4 => "Fix available", 3 => "Low risk, by a control", 2 => "Low risk", 1 => "Ignorable" }.freeze

  attr_reader :rows, :total

  def initialize(host_id)
    advisories = VulnerabilityFinding.active.where(host_id:).where.not(bucket: nil).joins(:advisory)
                                     .group(:advisory_id, "advisories.severity")
                                     .pluck("advisories.severity", Arel.sql(WORST_SQL), Arel.sql("bool_or(vulnerability_findings.kev)"), Arel.sql(KERNEL_SQL),
                                            Arel.sql(LISTENER_SQL))
    @rows = bucket_rows(advisories) + listener_rows(advisories)
    @total = @rows.sum(&:points)
  end

  # Advisories by severity, worst first: "1 high, 2 medium".
  def self.severity_words(severities) = Advisory::SEVERITIES.filter_map { |s| "#{severities[s]} #{s}" if severities[s].to_i.positive? }.join(", ")

  private

  def bucket_rows(advisories)
    groups = advisories.group_by do |_, worst, kev, kernel, _|
      [ -worst, kev && worst > 1 ? 0 : 1, worst == VulnerabilityExposure::WORST.fetch("fix") ? (kernel ? 0 : 1) : 0 ]
    end
    groups.sort.map do |(negative_worst, kev, step), list|
      worst = -negative_worst
      Row.new(key: "#{worst}-#{kev}-#{step}", label: label(worst, kev.zero?, step), advisories: list.size, severities: list.map(&:first).tally,
              points: list.sum { |severity, _, known, _, _| VulnerabilityExposure.base_points(worst:, severity:, kev: known) })
    end
  end

  def label(worst, kev, step)
    words = [ WORST_LABELS.fetch(worst) ]
    words << (step.zero? ? "a kernel step" : "package upgrades") if worst == VulnerabilityExposure::WORST.fetch("fix")
    words << "known exploited (doubled)" if kev
    words.join(", ")
  end

  def listener_rows(advisories)
    scored = advisories.select { |_, worst, _, _, listener| listener && worst > 1 }
    scored.group_by(&:last).sort_by { |listener, _| -listener }.map do |listener, list|
      Row.new(key: "listener-#{listener}", label: "Loaded by a process #{VulnerabilityExposure::LISTENER_NAMES.fetch(listener)} (added)",
              advisories: list.size, severities: list.map(&:first).tally,
              points: list.sum { |severity, worst, _, _, _| VulnerabilityExposure.listener_points(worst:, severity:, listener:) })
    end
  end
end
