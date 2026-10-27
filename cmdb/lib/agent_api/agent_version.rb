module AgentApi
  # Semantic version comparison (SemVer 2.0.0 precedence; build metadata ignored) for the minimum agent
  # version check (FR-S.2, NFR-5).
  class AgentVersion
    include Comparable

    # The SemVer 2.0.0 grammar, as in docs/api agent_version: no leading zeros in numeric identifiers, no
    # empty identifiers.
    NUMERIC = /0|[1-9]\d*/
    PRERELEASE_ID = /(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)/
    BUILD_ID = /[0-9A-Za-z-]+/
    PATTERN = /\A(#{NUMERIC})\.(#{NUMERIC})\.(#{NUMERIC})(?:-(#{PRERELEASE_ID}(?:\.#{PRERELEASE_ID})*))?(?:\+#{BUILD_ID}(?:\.#{BUILD_ID})*)?\z/

    attr_reader :core, :prerelease

    def self.parse(string)
      match = PATTERN.match(string.to_s) or return nil
      new(match[1..3].map(&:to_i), match[4]&.split(".") || [])
    end

    def initialize(core, prerelease)
      @core = core
      @prerelease = prerelease
    end

    def <=>(other)
      result = core <=> other.core
      return result unless result.zero?
      return 0 if prerelease == other.prerelease
      return 1 if prerelease.empty? # a release outranks its pre-releases
      return -1 if other.prerelease.empty?

      compare_prerelease(other.prerelease)
    end

    private

    def compare_prerelease(others)
      prerelease.zip(others).each do |mine, theirs|
        return 1 if theirs.nil?

        result = if mine.match?(/\A\d+\z/) && theirs.match?(/\A\d+\z/)
          mine.to_i <=> theirs.to_i
        elsif mine.match?(/\A\d+\z/) then -1
        elsif theirs.match?(/\A\d+\z/) then 1
        else mine <=> theirs
        end
        return result unless result.zero?
      end
      prerelease.size <=> others.size
    end
  end
end
