# The Low risk and Ignorable sections' rows on a host's Vulnerabilities tab (VT-HOST-TAB #260, VT-D04; approved mockup
# host-vulns.html): one row per rule with its count of findings and its largest package, read in one query whatever
# the host's finding count. Each row links to that rule's package rows (HostFindingGroups on the same findings).
class HostTriageRules
  Row = Data.define(:rule, :bucket, :count, :package, :package_count)

  attr_reader :rows

  # scope: the findings shown, a VulnerabilityFinding.with_details relation joined to advisories.
  def initialize(scope)
    per_package = scope.except(:order, :preload, :includes).reselect(
      Arel.sql("vulnerability_findings.bucket_rule AS rule_id"), Arel.sql("vulnerability_findings.package AS package_name"),
      Arel.sql("vulnerability_findings.architecture AS package_architecture"), Arel.sql("count(*) AS n"),
      Arel.sql("sum(count(*)) OVER (PARTITION BY vulnerability_findings.bucket_rule) AS total")
    ).group("vulnerability_findings.bucket_rule", "vulnerability_findings.package", "vulnerability_findings.architecture")
    query = VulnerabilityFinding.unscoped.with(r: per_package).from("r").select(Arel.sql("DISTINCT ON (r.rule_id) r.*"))
                                .order(Arel.sql("r.rule_id"), Arel.sql("r.n DESC"), Arel.sql('r.package_name COLLATE "C"'), Arel.sql('r.package_architecture COLLATE "C"'))
    @rows = VulnerabilityFinding.connection.select_all(query.arel, "HostTriageRules").map do |row|
      rule = VulnerabilityTriage.rule_for(row["rule_id"])
      Row.new(rule:, bucket: VulnerabilityTriage::RULES.fetch(rule), count: row["total"].to_i,
              package: "#{row['package_name']}:#{row['package_architecture']}", package_count: row["n"].to_i)
    end.sort_by { |row| [ -row.count, VulnerabilityTriage::RULE_IDS.fetch(row.rule) ] }
  end

  # The rows of one bucket ("low_risk" or "ignorable"), most findings first.
  def for(bucket) = rows.select { |row| row.bucket == bucket }
end
