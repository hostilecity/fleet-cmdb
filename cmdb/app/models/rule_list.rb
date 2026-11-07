# The rules list (P2-D06, approved mockup rules.html): every CIS-aligned rule with its current version and what it
# does across the fleet, built from query parameters so every view is linkable: q (title, key, or reference),
# severity, status, applies (a distribution, or distribution:release), result, sort (name, severity, status), dir,
# and page. Three queries whatever the number of rules: the rules, their current versions, and the results of hosts
# in the fleet counted by rule and result in the database.
class RuleList
  PER_PAGE = 50
  QUERY_MAX = 100
  SEVERITIES = %w[critical high medium low].freeze
  STATUSES = { "enabled" => "Enabled", "disabled" => "Disabled" }.freeze
  RESULTS = { "fail" => "Fails on a host", "not_readable" => "Not readable on a host", "pass" => "Passes everywhere" }.freeze
  SORTS = %w[name severity status].freeze
  EVALUATED = %w[pass fail not_readable not_applicable].freeze

  # What one rule does across the fleet: hosts by result (only hosts in the fleet), and evaluated, the hosts with a
  # real result (every host that has sent a config report, once the rule has been evaluated).
  Fleet = Data.define(:counts) do
    def [](result) = counts.fetch(result, 0)

    def evaluated = EVALUATED.sum { |result| self[result] }
  end

  Row = Data.define(:rule, :version, :fleet)

  attr_reader :q, :severity, :status, :applies, :result, :sort, :direction, :page

  def initialize(params = {})
    @q = params[:q].is_a?(String) ? params[:q].strip.first(QUERY_MAX).presence : nil
    @severity = SEVERITIES.include?(params[:severity]) ? params[:severity] : nil
    @status = STATUSES.key?(params[:status]) ? params[:status] : nil
    @applies = params[:applies].is_a?(String) && params[:applies].match?(/\A[a-z0-9][a-z0-9._-]{0,63}(:[A-Za-z0-9._~-]{1,64})?\z/) ? params[:applies] : nil
    @result = RESULTS.key?(params[:result]) ? params[:result] : nil
    @sort = SORTS.include?(params[:sort]) ? params[:sort] : "name"
    @direction = params[:dir] == "desc" ? "desc" : "asc"
    @page = params[:page].to_s.match?(/\A[1-9]\d{0,5}\z/) ? params[:page].to_i : 1
  end

  def all_rows
    @all_rows ||= begin
      rules = CisRule.includes(:current_version).to_a.select(&:current_version)
      counts = CisResult.joins(:host).merge(Host.in_fleet).where(cis_rule_id: rules.map(&:id)).group(:cis_rule_id, :result).count
      by_rule = counts.each_with_object(Hash.new { |hash, key| hash[key] = {} }) { |((rule_id, result), count), out| out[rule_id][result] = count }
      rules.map { |rule| Row.new(rule:, version: rule.current_version, fleet: Fleet.new(counts: by_rule[rule.id])) }
    end
  end

  def matching = @matching ||= sorted(all_rows.select { |row| match?(row) })

  def rows = matching.drop((page - 1) * PER_PAGE).first(PER_PAGE)

  def total = all_rows.size

  def enabled_count = all_rows.count { |row| row.rule.enabled }

  def pages = [ (matching.size + PER_PAGE - 1) / PER_PAGE, 1 ].max

  def first_shown = matching.empty? ? 0 : ((page - 1) * PER_PAGE) + 1

  def last_shown = [ page * PER_PAGE, matching.size ].min

  def filtered? = [ q, severity, status, applies, result ].any?

  # The "Applies to" filter's choices: [label, value] for every distribution, and distribution and release, the
  # rules name.
  def applies_options
    pairs = all_rows.flat_map do |row|
      row.version.applies_to.flat_map do |platform|
        distribution = platform["distribution"]
        versions = platform["versions"]
        versions ? versions.map { |version| [ "#{distribution} #{version}", "#{distribution}:#{version}" ] } : [ [ distribution, distribution ] ]
      end
    end
    pairs.uniq.sort_by(&:first)
  end

  # The query for the current list with some parameters changed (nil removes one); page goes back to 1 unless given.
  def params_with(**changes)
    query = { q:, severity:, status:, applies:, result:, sort: (sort unless sort == "name"), dir: (direction unless direction == "asc"), page: nil }.merge(changes)
    query[:page] = nil if query[:page] == 1
    query.compact
  end

  # Query parameters for a link that sorts by column, toggling direction when it is already the sort.
  def sort_params(column) = params_with(sort: column, dir: (sort == column && direction == "asc" ? "desc" : "asc"))

  def aria_sort(column)
    return "none" unless sort == column

    direction == "asc" ? "ascending" : "descending"
  end

  private

  def match?(row)
    version = row.version
    return false if severity && version.severity != severity
    return false if status && row.rule.enabled != (status == "enabled")
    return false if applies && !applies?(version.applies_to)
    return false if result && !result?(row)

    q.nil? || [ version.title, row.rule.key, version.reference ].any? { |text| text.downcase.include?(q.downcase) }
  end

  def applies?(platforms)
    distribution, version = applies.split(":", 2)
    platforms.any? { |platform| platform["distribution"] == distribution && (version.nil? || platform["versions"].nil? || platform["versions"].include?(version)) }
  end

  def result?(row)
    return false unless row.rule.enabled

    case result
    when "fail", "not_readable" then row.fleet[result].positive?
    else row.fleet["pass"].positive? && row.fleet["fail"].zero? && row.fleet["not_readable"].zero?
    end
  end

  def sorted(rows)
    name = ->(row) { [ row.version.title.downcase, row.rule.key ] }
    key = case sort
    when "severity" then ->(row) { [ SEVERITIES.index(row.version.severity), *name.(row) ] }
    when "status" then ->(row) { [ row.rule.enabled ? 0 : 1, *name.(row) ] }
    else name
    end
    sorted = rows.sort_by(&key)
    direction == "desc" ? sorted.reverse : sorted
  end
end
