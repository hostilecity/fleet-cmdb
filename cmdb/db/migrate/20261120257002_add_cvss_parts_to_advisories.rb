# The CVSS v3 attack vector, privileges required, and user interaction of each advisory (VT-S04, ADR 0032), parsed at
# import from the vector Advisories::Severity scores (Advisories::Cvss3.parts), for the triage rules N4, L2, and L3.
# Null when the advisory has no valid v3 vector (a v2 or v4 vector, a word, or an urgency). The advisories table is
# small (about 74,000 rows), so the columns and checks are added in one step; the next migration fills them.
class AddCvssPartsToAdvisories < ActiveRecord::Migration[8.1]
  def change
    add_column :advisories, :cvss_av, :string, limit: 1
    add_column :advisories, :cvss_pr, :string, limit: 1
    add_column :advisories, :cvss_ui, :string, limit: 1
    add_check_constraint :advisories, "cvss_av IN ('N', 'A', 'L', 'P') AND cvss_pr IN ('N', 'L', 'H') AND cvss_ui IN ('N', 'R') " \
                                      "OR cvss_av IS NULL AND cvss_pr IS NULL AND cvss_ui IS NULL", name: "advisories_cvss_parts_valid"
  end
end
