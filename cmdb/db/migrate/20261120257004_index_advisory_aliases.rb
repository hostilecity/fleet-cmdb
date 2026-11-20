# Finds the advisories naming a CVE through their aliases (VT-SIGNALS, #257): the KEV and EPSS panels count the CVEs that
# match open findings by looking each CVE up (Signals.matching_open_findings) rather than unnesting every advisory's
# aliases. A GIN index on about 74,000 advisories builds in about a second.
class IndexAdvisoryAliases < ActiveRecord::Migration[8.1]
  def change
    add_index :advisories, :aliases, using: :gin
  end
end
