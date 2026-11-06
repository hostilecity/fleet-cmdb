# Package version ordering by package manager (FR-2.4, P2-S09). Versions are never compared as strings: each
# manager has its own rules. Only dpkg is built, the one manager in the fleet profile (DEC-01); another scheme
# would be a module with the same interface (MANAGER, parse, valid?, compare), added here by a later decision.
#
#   PackageVersions.for("dpkg").compare("1.0-1", "1.0-1+deb13u1") # => -1
#   PackageVersions.sort(%w[2.0 1:0.1 bad:x 1.0~rc1], scheme: "dpkg") # => ["1.0~rc1", "2.0", "1:0.1", "bad:x"]
#
# compare returns :invalid when either version cannot be parsed, so matching (P2-S11) can record the package
# as not evaluated instead of guessing.
module PackageVersions
  Invalid = Data.define(:version, :reason)

  SCHEMES = { Dpkg::MANAGER => Dpkg }.freeze

  module_function

  # The scheme for a package manager name. Raises KeyError for one that has none.
  def for(manager) = SCHEMES.fetch(manager)

  # Sorts ascending by the scheme's order and never raises: valid versions first, equal ones in input order,
  # then invalid ones in input order.
  def sort(versions, scheme:)
    scheme = self.for(scheme) if scheme.is_a?(String)
    parsed = versions.each_with_index.map { |text, index| [ text, scheme.parse(text), index ] }
    valid, invalid = parsed.partition { |_, version, _| !version.is_a?(Invalid) }
    sorted = valid.sort { |(_, a, i), (_, b, j)| scheme.compare(a, b).nonzero? || (i <=> j) }
    (sorted + invalid).map(&:first)
  end
end
