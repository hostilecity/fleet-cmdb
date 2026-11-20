# Fills advisories.cvss_av, cvss_pr, and cvss_ui from the stored severity_raw (VT-S04): the raw value is the v3 vector
# when the severity rule used one (Advisories::Severity). One UPDATE per batch of ids, for speed: 74,000 advisories, all
# with a v3 vector, took about 6 s (one UPDATE a row took 111 s). The batches do not shorten locking: the migration is
# one transaction, so every advisory updated stays locked until it commits (about 6 s at that size, while nothing else
# writes advisories but the advisory import, which waits).
# No triage run exists before this (#259), so nothing is handed to one.
class BackfillAdvisoryCvssParts < ActiveRecord::Migration[8.1]
  BATCH = 2_000

  def up
    last = 0
    loop do
      rows = select_rows("SELECT id, severity_raw FROM advisories WHERE id > #{last} AND severity_raw LIKE 'CVSS:3.%' ORDER BY id LIMIT #{BATCH}")
      break if rows.empty?

      values = rows.filter_map do |id, raw|
        parts = Advisories::Cvss3.parts(raw)
        "(#{Integer(id)}, #{quote(parts[:av])}, #{quote(parts[:pr])}, #{quote(parts[:ui])})" if parts
      end
      if values.any?
        execute("UPDATE advisories a SET cvss_av = v.av, cvss_pr = v.pr, cvss_ui = v.ui " \
                "FROM (VALUES #{values.join(', ')}) AS v(id, av, pr, ui) WHERE a.id = v.id")
      end
      last = rows.last.first.to_i
    end
  end

  def down
    execute("UPDATE advisories SET cvss_av = NULL, cvss_pr = NULL, cvss_ui = NULL")
  end
end
