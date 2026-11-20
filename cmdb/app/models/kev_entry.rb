# One CVE in CISA's Known Exploited Vulnerabilities catalog (VT-S02, ADR 0032), as the last stored KEV import left it.
# Rule N1 uses it whatever its age (B1): staleness is shown at read time and never rewrites anything. Only the fields
# the triage and the screens use are kept; vendor and product are capped, cleaned text.
class KevEntry < ApplicationRecord
end
