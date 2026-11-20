require "rails_helper"
require Rails.root.join("db/migrate/20261120257003_backfill_advisory_cvss_parts")

# The one-off backfill of advisories.cvss_av, cvss_pr, and cvss_ui from the stored severity_raw (VT-S04, #257).
RSpec.describe BackfillAdvisoryCvssParts do
  def migrate(direction) = ActiveRecord::Migration.suppress_messages { described_class.new.migrate(direction) }

  it "fills the parts of advisories stored with a v3 vector, in batches, leaves the others null, and rolls back" do
    stub_const("BackfillAdvisoryCvssParts::BATCH", 1)
    v3 = advisory_for("CVE-2026-0001", severity_raw: "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H")
    broken = advisory_for("CVE-2026-0002", severity_raw: "CVSS:3.1/AV:N/AC:L")
    v4 = advisory_for("CVE-2026-0003", severity_raw: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    word = advisory_for("CVE-2026-0004", severity_raw: "urgency: high")
    migrate(:up)
    expect(v3.reload).to have_attributes(cvss_av: "A", cvss_pr: "L", cvss_ui: "R")
    [ broken, v4, word ].each { |advisory| expect(advisory.reload.cvss_av).to be_nil }
    migrate(:down)
    expect(v3.reload.cvss_av).to be_nil
  end
end
