# The bucket sections of a host's Vulnerabilities tab (VT-HOST-TAB #260, VT-D04; approved mockup host-vulns.html),
# each one page, loaded in a fixed number of statements whatever the host's finding count:
#
# - Fix available: the kernel's rows (K1, K2) first, since their action differs, then the package rows (F1, F2), each
#   HostFindingGroups (#253's rows and order) with its own cursor.
# - Needs attention: one row per advisory (HostAdvisoryGroups).
# - Low risk and Ignorable: one row per rule (HostTriageRules); rule: one rule of theirs whose package rows are shown.
# - Not triaged yet: the open findings with no bucket (a host the upgrade's background re-triage has not reached,
#   VT-BUCKETS' migration; #277 item 15), as #253's package rows, only when there are any.
#
# Then the triage inputs of every finding on the page (VulnerabilityTriage::Explain, for the reasons) and the KEV dates
# and EPSS scores of their CVEs, for the reasons and the signals. scope: the open and reopened findings the filters
# keep, a VulnerabilityFinding.with_details relation joined to advisories. bucket: the one section to show (?bucket=),
# or nil for all. cursors: { section => [after, before] } as parameters. untriaged: how many open findings have no
# bucket. decisions: the host's HostDecisions (VT-OVERRIDES #261), for the decision column and O1's reasons.
class HostTriageSections
  BUCKETS = %w[fix attention low_risk ignorable untriaged].freeze
  KERNEL_RULES = %w[K1 K2].freeze
  PACKAGE_RULES = %w[F1 F2].freeze
  RULE_BUCKETS = %w[low_risk ignorable].freeze
  CURSORS = %w[kernel fix attention rule untriaged].freeze
  # Findings shown under one package row; the rest are on its package page, so a package with thousands of findings
  # (a running kernel's L2) neither renders nor explains them all (review of #281, N3). Worst severity first.
  NESTED_MAX = 200

  attr_reader :decisions, :bucket, :rule, :kernel, :packages, :attention, :rules, :rule_groups, :untriaged, :inputs, :kev_dates, :epss_scores

  # The rule of a ?rule= parameter when it is one of Low risk's or Ignorable's, else nil.
  def self.rule_param(value) = VulnerabilityTriage::RULES.key?(value) && RULE_BUCKETS.include?(VulnerabilityTriage::RULES[value]) ? value : nil

  def initialize(scope, bucket: nil, rule: nil, cursors: {}, untriaged: 0, decisions: nil, now: Time.current)
    @decisions = decisions
    @bucket = bucket
    @rule = rule && shown?(VulnerabilityTriage::RULES.fetch(rule)) ? rule : nil
    @cursors = cursors
    if shown?("fix")
      @kernel = groups(scope.where(bucket_rule: ids(KERNEL_RULES)), "kernel")
      @packages = groups(scope.where(bucket_rule: ids(PACKAGE_RULES)), "fix")
    end
    @attention = advisory_groups(scope.where(bucket: VulnerabilityTriage::BUCKETS.fetch("attention"))) if shown?("attention")
    @rules = HostTriageRules.new(scope.where(bucket: VulnerabilityTriage::BUCKETS.values_at(*RULE_BUCKETS))) if RULE_BUCKETS.any? { |name| shown?(name) }
    @rule_groups = groups(scope.where(bucket_rule: VulnerabilityTriage::RULE_IDS.fetch(@rule)), "rule") if @rule
    @untriaged = groups(scope.where(bucket: nil), "untriaged") if untriaged.positive? && shown?("untriaged")
    load_details(now)
  end

  def shown?(name) = bucket.nil? || bucket == name

  # The findings drawn under a package row.
  def self.shown(group) = group.findings.first(NESTED_MAX)

  # The package page's sections (#283): the tab sections with package rows, whose "N more" link carries its section
  # so the package page lists exactly the findings the row counts. A section's findings, as the tab selects them
  # below: Fix available's kernel rows (K1, K2) or package rows (F1, F2), one Low risk or Ignorable rule's rows, or
  # the open findings not triaged yet. scope: open and reopened findings; rule: a rule_param, for "rule".
  PACKAGE_SECTIONS = %w[kernel fix rule untriaged].freeze

  def self.section_scope(scope, section, rule = nil)
    case section
    when "kernel" then scope.where(bucket_rule: KERNEL_RULES.map { |name| VulnerabilityTriage::RULE_IDS.fetch(name) })
    when "fix" then scope.where(bucket_rule: PACKAGE_RULES.map { |name| VulnerabilityTriage::RULE_IDS.fetch(name) })
    when "rule" then scope.where(bucket_rule: VulnerabilityTriage::RULE_IDS.fetch(rule))
    else scope.where(bucket: nil)
    end
  end

  # Every finding on the page, and every finding of a Fix available package row: its "Upgrade to" is the highest fix
  # of all of them, which F2's needs their inputs for (re-check of #281, N3). Fix available rows are upgrades, so
  # rarely long.
  def findings
    Array(packages&.groups).flat_map(&:findings) +
      [ kernel, rule_groups, untriaged ].compact.flat_map { |list| list.groups.flat_map { |group| self.class.shown(group) } } +
      Array(attention&.groups).flat_map(&:findings)
  end

  private

  def ids(rules) = rules.map { |rule| VulnerabilityTriage::RULE_IDS.fetch(rule) }

  def cursor(section) = @cursors.fetch(section, [])

  def groups(scope, section)
    after, before = cursor(section)
    HostFindingGroups.new(scope, rank: :offenders, after: HostFindingGroups.cursor(after, :offenders), before: HostFindingGroups.cursor(before, :offenders))
  end

  def advisory_groups(scope)
    after, before = cursor("attention")
    HostAdvisoryGroups.new(scope, after: HostAdvisoryGroups.cursor(after), before: HostAdvisoryGroups.cursor(before))
  end

  def load_details(now)
    @inputs = VulnerabilityTriage::Explain.load(findings, now:)
    cves = @inputs.values.flat_map(&:cve_ids).uniq
    @kev_dates = KevEntry.where(cve_id: cves).pluck(:cve_id, :date_added).to_h
    @epss_scores = EpssScore.where(cve_id: cves).pluck(:cve_id, :score).to_h
  end
end
