# One page of a sorted host list, by keyset (#193): the fleet list and the compliance page read the rows after (or before)
# the cursor host in index order, so a page costs the same on page 1 and page 1,000, whatever the fleet size, as on the
# task list and the audit log. The cursor is a host id; the page boundary is that host's sort keys as they are now, read
# in the same query, so a cursor needs no encoding and cannot carry a value the database would not have written.
#
# keys: the sort, ending in a unique key; each ascending or descending, and nullable keys have their NULLs last in either
# direction. A boundary is one row comparison when the keys after the first nullable or direction change all agree;
# otherwise it is the disjunction "equal so far, then beyond", each part a range of one index read in order, joined
# with UNION ALL and each limited to a page, so the database never reads more than a few pages of index.
class KeysetPage
  Key = Data.define(:sql, :descending, :nullable) do
    def initialize(sql:, descending: false, nullable: false) = super
  end

  ID_FORMAT = /\A[1-9]\d{0,17}\z/ # a positive bigint, without leading zeros

  # The cursor parameters: { after: id } or { before: id }, validated, after ignored when before is given.
  def self.cursor(params)
    before = params[:before].to_s.match?(ID_FORMAT) ? params[:before].to_i : nil
    after = params[:after].to_s.match?(ID_FORMAT) && before.nil? ? params[:after].to_i : nil
    { after:, before: }.compact
  end

  attr_reader :rows, :previous, :next

  # scope: the filtered rows (no order). lookup: the same tables unfiltered, to read the cursor host's keys.
  def initialize(scope:, keys:, lookup:, per_page:, after: nil, before: nil)
    @scope = scope
    @keys = keys
    @lookup = lookup
    @per_page = per_page
    load(after:, before:)
  end

  private

  def load(after:, before:)
    cursor = before || after
    nulls = cursor && @lookup.where(id: cursor).pick(*@keys.map { |key| Arel::Nodes::Grouping.new(Arel.sql(key.sql)).eq(nil) })
    if nulls && before
      rows = fetch(cursor, nulls, reverse: true)
      # Previous from the second page, or from a page whose hosts before it went: the first page, full.
      return first_page if rows.size <= @per_page

      @rows = rows.first(@per_page).reverse
      @previous = { before: @rows.first.id }
      @next = { after: @rows.last.id }
    elsif nulls
      rows = fetch(cursor, nulls, reverse: false)
      @rows = rows.first(@per_page)
      @previous = @rows.any? ? { before: @rows.first.id } : nil
      @next = rows.size > @per_page ? { after: @rows.last.id } : nil
    else
      first_page # no cursor, or one naming no host
    end
  end

  def first_page
    rows = @scope.order(*order(reverse: false)).limit(@per_page + 1).to_a
    @rows = rows.first(@per_page)
    @previous = nil
    @next = rows.size > @per_page ? { after: @rows.last.id } : nil
  end

  def fetch(cursor, nulls, reverse:)
    parts = boundary(cursor, nulls, reverse)
    return @scope.where(parts.first).order(*order(reverse:)).limit(@per_page + 1).to_a if parts.one?

    keyed = @keys.each_with_index.map { |key, i| key.with(sql: "keyset_#{i}") }
    union = parts.each_with_index.map do |condition, i|
      columns = [ Arel::Nodes.build_quoted(i).as("keyset_part"), *@keys.each_with_index.map { |key, j| Arel.sql(key.sql).as("keyset_#{j}") } ]
      Arel::Nodes::Grouping.new(@scope.where(condition).select(*columns).order(*order(reverse:)).limit(@per_page + 1).arel)
    end.reduce { |all, part| Arel::Nodes::UnionAll.new(all, part) }
    @scope.klass.from(Arel::Nodes::TableAlias.new(Arel::Nodes::Grouping.new(union), @scope.klass.table_name))
          .order(Arel.sql("keyset_part"), *order(reverse:, keys: keyed)).limit(@per_page + 1).to_a
  end

  # The ORDER BY of the list, or of its reverse; nullable keys keep their NULLs last in either direction, the others
  # PostgreSQL's default, so a reverse read is the same index read backwards.
  def order(reverse:, keys: @keys)
    keys.map do |key|
      ordering = key.descending ^ reverse ? Arel.sql(key.sql).desc : Arel.sql(key.sql).asc
      next ordering unless key.nullable

      reverse ? ordering.nulls_first : ordering.nulls_last
    end
  end

  # The rows strictly past the cursor host in the direction of travel, as disjoint conditions in the order they are
  # read: equal on the longest prefix first, then beyond on each shorter one.
  def boundary(cursor, nulls, reverse)
    value = ->(i) { "(#{@lookup.where(id: cursor).select(Arel.sql(@keys[i].sql)).to_sql})" }
    descending = ->(i) { @keys[i].descending ^ reverse }
    past = ->(i) { descending.(i) ? "<" : ">" }
    equal = ->(i) { nulls[i] ? "#{@keys[i].sql} IS NULL" : "#{@keys[i].sql} = #{value.(i)}" }
    tail = @keys.size - 1
    tail -= 1 while tail.positive? && !@keys[tail - 1].nullable && descending.(tail - 1) == descending.(tail)

    columns = (tail...@keys.size).to_a
    row = if columns.one?
      "#{@keys[tail].sql} #{past.(tail)} #{value.(tail)}"
    else
      "(#{columns.map { |i| @keys[i].sql }.join(', ')}) #{past.(tail)} (#{columns.map(&value).join(', ')})"
    end
    parts = [ [ *(0...tail).map(&equal), row ] ]
    (tail - 1).downto(0) do |i|
      prefix = (0...i).map(&equal)
      beyond(i, nulls[i], reverse, value, past).each { |condition| parts << [ *prefix, condition ] }
    end
    parts.map { |conditions| Arel.sql(conditions.join(" AND ")) }
  end

  # Values past one key's: NULLs come last going forward, so past a NULL is nothing going forward and every value
  # going back.
  def beyond(i, null, reverse, value, past)
    key = @keys[i]
    if null
      reverse ? [ "#{key.sql} IS NOT NULL" ] : []
    else
      [ "#{key.sql} #{past.(i)} #{value.(i)}", *("#{key.sql} IS NULL" if key.nullable && !reverse) ]
    end
  end
end
