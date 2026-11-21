# FIRST's EPSS score for one CVE named by a stored advisory (VT-S03, ADR 0032), as the last stored EPSS import left
# it. band is "high" from a score of FLEET_EPSS_ENTER (0.10) until it falls below FLEET_EPSS_LEAVE (0.07), so a score
# near the line does not move findings every day; rule N2 uses the stored band whatever its age (B1).
class EpssScore < ApplicationRecord
  BANDS = %w[high normal].freeze
end
