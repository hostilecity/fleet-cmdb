module Advisories
  # The CVSS v3.0 and v3.1 base score of a vector string (FIRST's specification, section 7), for the severity
  # rule in Advisories::Severity. Returns nil for anything that is not a complete, valid v3 base vector.
  #
  #   Advisories::Cvss3.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") # => 9.8
  module Cvss3
    WEIGHTS = {
      "AV" => { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2 },
      "AC" => { "L" => 0.77, "H" => 0.44 },
      "PR" => { "N" => 0.85, "L" => 0.62, "H" => 0.27 },
      "UI" => { "N" => 0.85, "R" => 0.62 },
      "S" => { "U" => nil, "C" => nil },
      "C" => { "H" => 0.56, "L" => 0.22, "N" => 0.0 },
      "I" => { "H" => 0.56, "L" => 0.22, "N" => 0.0 },
      "A" => { "H" => 0.56, "L" => 0.22, "N" => 0.0 }
    }.freeze
    # Privileges required weigh more when the scope changes.
    PR_CHANGED = { "N" => 0.85, "L" => 0.68, "H" => 0.5 }.freeze
    PREFIX = %r{\ACVSS:3\.[01]/}

    module_function

    def base_score(vector)
      return nil unless vector.is_a?(String) && vector.match?(PREFIX)

      metrics = vector.sub(PREFIX, "").split("/").to_h { |part| part.split(":", 2) }
      return nil unless WEIGHTS.all? { |metric, values| values.key?(metrics[metric]) }

      changed = metrics["S"] == "C"
      iss = 1 - %w[C I A].map { |m| 1 - WEIGHTS[m][metrics[m]] }.reduce(:*)
      impact = changed ? 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02)**15) : 6.42 * iss
      pr = (changed ? PR_CHANGED : WEIGHTS["PR"])[metrics["PR"]]
      exploitability = 8.22 * WEIGHTS["AV"][metrics["AV"]] * WEIGHTS["AC"][metrics["AC"]] * pr * WEIGHTS["UI"][metrics["UI"]]
      return 0.0 if impact <= 0

      roundup([ (changed ? 1.08 : 1) * (impact + exploitability), 10 ].min)
    end

    # The specification's Roundup (v3.1, appendix A): the smallest one-decimal number not below x, computed on
    # integers so that floating point error does not round 4.0000001 up to 4.1.
    def roundup(x)
      int = (x * 100_000).round
      (int % 10_000).zero? ? int / 100_000.0 : ((int / 10_000) + 1) / 10.0
    end
  end
end
