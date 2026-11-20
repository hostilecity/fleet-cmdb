# Debian's signed-template source packages (#270, ADR 0011): a binary whose reported source is linux-signed-amd64 or
# shim-signed is matched as linux or shim, the source Debian's advisories name, with that source's version read
# from the binary's. The table is cmdb/config/signed_sources.yml (SignedSources.table, checked when the server
# starts), which says why each row is there and why grub and fwupd's signed packages are not. This module is the
# only place the mapping is made: chunk matching, the resolution of a finding, and finding the chunks and hosts an
# advisory change touches all go through it.
module SignedSources
  # One row: the source the advisories name, the version rule, and the binaries it covers (nil: all of them).
  Rule = Data.define(:signed, :source, :version, :binaries) do
    def covers?(name) = binaries.nil? || binaries.include?(name)
  end

  # What a package is matched as: the advisories' source, and the version to compare (nil, with problem saying why,
  # when it cannot be read; the package is then not evaluated against that source's advisories).
  Target = Data.define(:source, :version, :problem)

  VERSIONS = %w[binary after_signed_version].freeze
  NAME = /\A[a-z0-9][a-z0-9+._-]{0,127}\z/ # the package report contract's names

  module_function

  # { "Debian" => { signed name => Rule } }
  def table = Rails.configuration.x.signed_sources

  def rules(ecosystem) = table.fetch(ecosystem.to_s.split(":").first, {})

  # The source and version a package (name, its reported source or nil, its version) is matched as in the
  # ecosystem: the reported source and version unless the table has a row for them.
  def resolve(ecosystem, name, source, version)
    source ||= name
    rule = rules(ecosystem)[source]
    return Target.new(source, version, nil) unless rule&.covers?(name)

    return Target.new(rule.source, version, nil) if rule.version == "binary"

    unsigned = after_signed_version(version)
    return Target.new(rule.source, unsigned, nil) if unsigned

    Target.new(rule.source, nil, "the #{rule.source} version built into #{name} #{version} cannot be read from it (#{source}: <#{source} version>+<#{rule.source} version>)")
  end

  # The reported source names whose packages can match advisories for sources: sources and every signed source that
  # maps to one of them, in the ecosystem (every ecosystem when nil), for COALESCE(source, name) IN (...).
  def reported(sources, ecosystem = nil)
    sources = Array(sources)
    rows = ecosystem ? rules(ecosystem).values : table.values.flat_map(&:values)
    (sources + rows.select { |rule| sources.include?(rule.source) }.map(&:signed)).uniq
  end

  # The advisories' sources the table maps to, in the ecosystem: what changed meaning when the table changed.
  def sources(ecosystem) = rules(ecosystem).values.map(&:source).uniq.sort

  # "<signed version>+<source version>" -> the source version, or nil when no "+" or more than one could start it:
  # the signed version is native (no "-"), and the source version starts with a digit and has a "-".
  def after_signed_version(version)
    prefix_end = version.index("-") || 0
    candidates = (0...prefix_end).select { |i| version[i] == "+" && i.positive? && version[i + 1]&.match?(/\d/) }
    candidates.size == 1 ? version[(candidates.first + 1)..] : nil
  end

  # Reads and checks the table file: { ecosystem family => { signed name => Rule } }. Raises with the file and row.
  def load(file)
    data = YAML.safe_load_file(file)
    raise "#{file}: must map an ecosystem family (Debian) to a list of rows" unless data.is_a?(Hash) && data.any?

    data.to_h do |family, rows|
      raise "#{file}: #{family} must be a list of { signed, source, version } rows" unless family.to_s.match?(/\A[A-Za-z][A-Za-z0-9.-]{0,31}\z/) && rows.is_a?(Array)

      [ family, rows.each_with_object({}) { |row, rules| add_rule(file, rules, row) }.freeze ]
    end.freeze
  end

  def add_rule(file, rules, row)
    signed, source, version, binaries = row.is_a?(Hash) ? row.values_at("signed", "source", "version", "binaries") : []
    valid = [ signed, source ].all? { |name| name.is_a?(String) && name.match?(NAME) } && signed != source && VERSIONS.include?(version) &&
            (binaries.nil? || (binaries.is_a?(Array) && binaries.any? && binaries.all? { |name| name.is_a?(String) && name.match?(NAME) })) &&
            (row.keys - %w[signed source version binaries]).empty?
    raise "#{file}: #{row.inspect} must have a signed and a source package name, a version rule (#{VERSIONS.join(' or ')}), and optionally binaries" unless valid
    raise "#{file}: #{signed} is listed twice" if rules.key?(signed)

    rules[signed] = Rule.new(signed:, source:, version:, binaries: binaries&.freeze)
  end

  private_class_method :add_rule
end
