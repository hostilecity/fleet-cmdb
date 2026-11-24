# A source package's current version in a release backports are built from (#304; the migration says why).
class BackportSourceVersion < ApplicationRecord
  self.primary_key = %i[ecosystem package]

  # { source => version } in the ecosystem, for the sources.
  def self.of(ecosystem, sources)
    return {} if sources.empty?

    where(ecosystem:, package: sources.uniq).pluck(:package, :version).to_h
  end
end
