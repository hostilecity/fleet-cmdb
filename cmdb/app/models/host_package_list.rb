# One page of a host's installed packages (P2-D03, FR-2.3, owner decision Q15 on the P2-D01 review): server-side
# search, filters, sort, and pages of PER_PAGE, all from query parameters so every view can be bookmarked, as on
# the fleet list (FleetList). q matches the package or source package name; arch is one architecture; findings
# "open" keeps packages with an open or reopened vulnerability finding. A page is three queries whatever the
# number of packages: the count, the rows, and the open findings of the rows shown.
class HostPackageList
  PER_PAGE = 50
  QUERY_MAX = 100
  # Version sorts as text: dpkg's order cannot be expressed in SQL, and the diff, not the list, says which way a
  # version moved.
  SORTS = { "name" => "host_packages.name", "version" => "host_packages.version", "source" => "host_packages.source" }.freeze
  ORDERS = SORTS.transform_values do |sql|
    expression = Arel.sql(sql)
    { "asc" => expression.asc.nulls_last, "desc" => expression.desc.nulls_last }.freeze
  end.freeze
  OPEN_FINDING = <<~SQL.squish.freeze
    EXISTS (SELECT 1 FROM vulnerability_findings f WHERE f.host_id = host_packages.host_id AND f.package = host_packages.name
            AND f.architecture = host_packages.architecture AND f.state IN ('open', 'reopened'))
  SQL

  # Open findings for one package on the page: how many, and whether any was reopened.
  Findings = Data.define(:open, :reopened)

  attr_reader :host_id, :q, :arch, :findings, :sort, :direction, :architectures

  def initialize(host_id, params = {})
    @host_id = host_id
    @architectures = HostPackage.where(host_id:).distinct.order(:architecture).pluck(:architecture)
    @q = params[:q].to_s.strip.first(QUERY_MAX).presence
    @arch = @architectures.include?(params[:arch]) ? params[:arch] : nil
    @findings = params[:findings] == "open" ? "open" : nil
    @sort = SORTS.key?(params[:sort]) ? params[:sort] : "name"
    @direction = params[:dir] == "desc" ? "desc" : "asc"
    @requested_page = [ params[:page].to_i, 1 ].max
  end

  def scope
    scope = HostPackage.where(host_id:)
    scope = scope.where("host_packages.name ILIKE :p OR host_packages.source ILIKE :p", p: "%#{HostPackage.sanitize_sql_like(q)}%") if q
    scope = scope.where(architecture: arch) if arch
    scope = scope.where(OPEN_FINDING) if findings
    scope
  end

  def total = @total ||= scope.count
  def pages = [ (total + PER_PAGE - 1) / PER_PAGE, 1 ].max
  def page = [ @requested_page, pages ].min
  def first_row = total.zero? ? 0 : (page - 1) * PER_PAGE + 1
  def last_row = [ page * PER_PAGE, total ].min

  def packages
    @packages ||= scope.order(ORDERS.fetch(sort).fetch(direction), :name, :architecture).offset((page - 1) * PER_PAGE).limit(PER_PAGE).to_a
  end

  # { [name, architecture] => Findings } for the packages on this page that have open findings.
  def open_findings
    @open_findings ||= begin
      counts = VulnerabilityFinding.active.where(host_id:, package: packages.map(&:name).uniq).group(:package, :architecture, :state).count
      counts.each_with_object({}) do |((name, architecture, state), count), out|
        current = out[[ name, architecture ]] || Findings.new(open: 0, reopened: false)
        out[[ name, architecture ]] = Findings.new(open: current.open + count, reopened: current.reopened || state == "reopened")
      end
    end
  end

  def filtered? = q.present? || arch.present? || findings.present?

  # The query parameters of this view, with some changed (nil removes one), for sort links and pages.
  def params_with(**changes)
    { q:, arch:, findings:, sort: (sort unless sort == "name"), dir: (direction unless direction == "asc") }.merge(changes).compact
  end

  # Query parameters for a link that sorts by column, toggling direction when it is already the sort.
  def sort_params(column) = params_with(sort: column, dir: (sort == column && direction == "asc" ? "desc" : nil), page: nil)

  def aria_sort(column)
    return "none" unless sort == column

    direction == "asc" ? "ascending" : "descending"
  end
end
