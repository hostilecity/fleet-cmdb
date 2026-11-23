require "rails_helper"

# The exposure tier, points, work items, and run badge on the pages (VT-SCORES #262, VT-D06 and VT-D04's additions;
# mockups tiles.html, fleet.html, states.html): the host summary tiles, the score breakdown and the run badge on the
# Vulnerabilities tab, the fleet list's honesty rules for a stale host, KEV qualifiers, and a fixed number of
# statements for the new sorts. Findings are written with their stored bucket, as the transitions leave them.
RSpec.describe "Host exposure", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let(:host) { enrolled_host(name: "Media server").first.tap { |h| package_set!(h) && vulns_evaluated!(h) } }
  let(:tab) { "/hosts/#{host.id}/vulnerabilities" }

  def words(node) = node&.xpath(".//text()")&.map(&:text)&.join(" ")&.squish

  def backdate(of = host, **times) = HostComplianceSummary.where(host_id: of.id).update_all(times.transform_values { |ago| Time.current - ago })

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-99001", package: "nothing-installed"), full: true) # the advisory data is current
    import_kev(kev_file("CVE-2026-99999"))
  end

  it "shows the tier, points, and work on the tiles, why the points on the tab, and the run, each in its own unit" do
    findings!(host, "high", rule: "N4", source: "bash")
    findings!(host, "medium", rule: "F1", source: "openssl")
    findings!(host, "low", rule: "K1", source: "linux")
    findings!(host, "critical", rule: "L2", source: "linux")
    findings!(host, "critical", rule: "I1", kev: true, source: "linux") # no points in Ignorable, KEV or not
    VulnerabilityWorkEvent.create!(host:, kind: "upgrade", subject: "curl", findings_cleared: 3, occurred_at: 2.days.ago)
    get tab
    expect(response).to have_http_status(:ok)
    expect(page.css("#host_summary > *").map { |tile| tile.at_css(".label").text }).to eq([ "CIS-aligned checks", "Vulnerability exposure", "Work remaining", "Last reports received" ])
    expect(words(page.at_css("#glance_exposure"))).to eq("Vulnerability exposure Exposed, no fix 27 points · 1 finding needs attention")
    expect(page.at_css("#glance_exposure")["href"]).to eq("#{tab}#score")
    expect(page.at_css("#glance_exposure .tier.t3")).not_to be_nil
    expect(words(page.at_css("#glance_work"))).to eq("Work remaining 2 work items 1 upgrade and a reboot · clears 2 findings 1 of 3 1 of 3 done in 30 days")
    expect(page.at_css("#glance_work meter").to_h.slice("min", "max", "value")).to eq("min" => "0", "max" => "3", "value" => "1")

    # The score breakdown: advisories by worst bucket, with their points, adding up to the tile's.
    expect(words(page.at_css("#score_heading"))).to eq("Why 27 points: Exposed, no fix")
    expect(page.css("#score_table tbody tr").map { |tr| words(tr) }).to eq([
      "Needs attention 1 high 1 20", "Fix available, a kernel step 1 low 1 1", "Fix available, package upgrades 1 medium 1 4",
      "Low risk 1 critical 1 2", "Ignorable 1 critical 1 0"
    ])
    expect(words(page.at_css("#score_table tfoot"))).to eq("Total 27")
    expect(page.at_css("#score_pending")).to be_nil
    expect(page.at_css("#score_tier").text.squish).to start_with("The tier is Exposed, no fix: a critical or high advisory needs attention and has no fix.")
    expect(page.css("#score_rules tbody tr").size).to eq(7) # the five buckets and the two listener rows

    # The run: no fixable critical since the host was scored.
    expect(words(page.at_css("#run_badge"))).to eq("No fixable critical for less than a day")
    backdate(no_fixable_critical_since: 12.days)
    get tab
    expect(words(page.at_css("#run_badge"))).to eq("No fixable critical for 12 days")
    expect(page.at_css("#run_badge.honest.streak")).not_to be_nil
    findings!(host, "critical", rule: "F1", source: "libxml2")
    backdate(fixable_critical_since: 3.days)
    get tab
    expect(words(page.at_css("#run_badge"))).to eq("12-day run · 1 fixable critical, 4 days left")
    shown = %w[#host_summary #score #run].map { |id| words(page.at_css(id)) }.join(" ")
    expect(shown).not_to match(/\b(secure|safe|clean|compliant|protected)\b/i) # VT-M5 rule 1
  end

  it "withholds the run and never shows 0 points or Nothing to install on a host whose package report is old" do
    HostPackageSet.where(host:).update_all(received_at: 5.days.ago)
    get tab
    expect(words(page.at_css("#run_badge"))).to eq("Run withheld: last package report 5 days ago")
    expect(page.at_css("#run_badge.withheld")).not_to be_nil
    expect(words(page.at_css("#glance_exposure"))).to eq("Vulnerability exposure Not known Last package report 5 days ago")
    expect(words(page.at_css("#glance_work"))).to eq("Work remaining Not known Last package report 5 days ago")
    get "/"
    expect(page.css("tr#row_host_#{host.id} td").map { |td| words(td) }[5..6]).to eq([ "Not known last package report 5 days ago", "Not known last package report 5 days ago" ])

    findings!(host, "high", rule: "F1", source: "openssl")
    get tab
    expect(words(page.at_css("#glance_exposure"))).to eq("Vulnerability exposure Fixes waiting 10 points · 0 need attention · as of the package report 5 days ago")
    expect(words(page.at_css("#glance_work"))).to eq("Work remaining 1 work item 1 upgrade · clears 1 finding progress withheld: last package report 5 days ago")
    get "/"
    expect(page.css("tr#row_host_#{host.id} td").map { |td| words(td) }[5..6])
      .to eq([ "Fixes waiting 10 points · 0 need attention · as of the package report 5 days ago", "1 work item 1 upgrade, as of the package report 5 days ago" ])
    Setting.update_vulnerability_badges!(actor: Audit::SYSTEM, report_max_age: "7")
    get tab
    expect(words(page.at_css("#progress_text"))).to start_with("0 of 1 work item done")
  end

  it "says Nothing to install with what needs attention, and the run, on the fleet list; withholds it while the advisory data is stale" do
    findings!(host, "medium", rule: "N4")
    backdate(no_fixable_critical_since: 41.days)
    get "/"
    expect(words(page.at_css("tr#row_host_#{host.id} td:nth-child(7)"))).to eq("Nothing to install 1 finding needs attention, no fix yet No fixable critical for 41 days")
    AdvisoryImport.update_all(finished_at: 10.days.ago)
    get "/"
    expect(words(page.at_css("tr#row_host_#{host.id} td:nth-child(7)"))).to eq("Nothing to install 1 finding needs attention, no fix yet")
    get tab
    expect(words(page.at_css("#run_badge"))).to eq("Run withheld: the advisory data is out of date")
  end

  it "names a stale or never-imported KEV source beside the tier, never a lower tier" do
    findings!(host, "high", rule: "F1", kev: true)
    SignalImport.where(signal: "kev").update_all(finished_at: Time.utc(2026, 11, 1, 9))
    get tab
    expect(words(page.at_css("#glance_exposure"))).to eq("Vulnerability exposure Known exploited 20 points · 1 known exploited · 0 need attention · not re-checked against KEV since 2026-11-01")
    expect(page.at_css("#score_tier").text.squish).to include("The tier and points are not re-checked against KEV since 2026-11-01: KEV listings are not shown as a lower tier.")
    get "/"
    expect(words(page.at_css("tr#row_host_#{host.id} td:nth-child(6)"))).to eq("Known exploited 20 points · 0 need attention · not re-checked against KEV since 2026-11-01")
  end

  it "shows no tier, points, or score breakdown on a host that is not evaluated or not triaged yet" do
    findings!(host, "high") # no bucket yet
    get tab
    expect(words(page.at_css("#glance_exposure"))).to eq("Vulnerability exposure Not triaged yet The re-triage after an upgrade has not reached this host yet")
    expect(page.at_css("#score")).to be_nil
    expect(page.at_css("#run_badge")).to be_nil
    get "/"
    expect(page.css("tr#row_host_#{host.id} td").map { |td| words(td) }[5..6]).to eq([ "Not triaged yet", "Not counted yet" ])
  end

  it "lists the reboot the agent reports as required as a work item, with the packages that asked for it" do
    HostApplicability.create!(host:, reboot_required: true, reboot_packages: [ "libc6", "<b>dbus</b>" ], reboot_changed_at: Time.current)
    get tab
    expect(words(page.at_css("#work_reboot_flag"))).to start_with("Reboot : the host reports that one is required, for libc6 , <b>dbus</b> .")
    expect(page.at_css("#work_reboot_flag b")).to be_nil # escaped
    expect(words(page.at_css("#glance_work"))).to eq("Work remaining 1 work item a reboot · clears 0 findings 0 of 1 0 of 1 done in 30 days")
  end

  it "reads the fleet list sorted by exposure or work in a fixed number of statements" do
    sort = ->(name) { count_queries { get "/", params: { sort: name } } }
    3.times { |i| enrolled_host.first.tap { |h| package_set!(h) && vulns_evaluated!(h) && findings!(h, "high", rule: i.even? ? "N4" : "F1") } }
    get "/" # warm up
    few = %w[exposure work].map(&sort)
    20.times { enrolled_host.first.tap { |h| package_set!(h) && vulns_evaluated!(h) && findings!(h, "low", rule: "F1") } }
    expect(%w[exposure work].map(&sort)).to eq(few)
  end
end
