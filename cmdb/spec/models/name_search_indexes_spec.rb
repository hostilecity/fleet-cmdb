require "rails_helper"

# Substring search over host names, hostnames, and operator emails (the fleet search and the audit log's
# target and actor filters) is ILIKE '%text%', which only a trigram index can serve. Without one every such
# request reads the whole table, which at fleet scale is hundreds of milliseconds (review of #71).
RSpec.describe "Name search indexes" do
  def plan(sql)
    ActiveRecord::Base.connection.select_values("EXPLAIN #{sql}").join("\n")
  end

  # The test tables are tiny, so the planner would rightly prefer a sequential scan; turning that off for
  # this transaction shows whether an index can serve the query at all.
  around do |example|
    ActiveRecord::Base.connection.execute("SET LOCAL enable_seqscan = off")
    example.run
  end

  it "serves the fleet and audit substring matches from trigram indexes" do
    hosts = Host.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: "%vm-01%").select(:id)
    expect(plan(hosts.to_sql)).to include("index_hosts_on_name_trigram", "index_hosts_on_hostname_trigram")

    operators = Operator.where("operators.email ILIKE ?", "%alex%").select(:id)
    expect(plan(operators.to_sql)).to include("index_operators_on_email_trigram")
  end
end
