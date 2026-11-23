require "rails_helper"

# The fleet list and host detail pages (FR-1.5, P1-D02, P1-D03).
RSpec.describe "Hosts", :signed_in, type: :request do
  # Page notices, without the hidden live-update banner and the flash.
  def notice = page.at_css(".notice:not(.flash):not([data-live-status-target])")

  def row_names = page.css("tbody tr td:first-child > a:first-child").map(&:text)

  def words(node) = node.text.squish

  def query(link) = Rack::Utils.parse_query(URI(link["href"]).query)

  describe "GET / (fleet list)" do
    it "shows the empty state when there are no hosts" do
      get "/"
      expect(response).to have_http_status(:ok)
      expect(response.body).to include("No hosts in the fleet.")
      expect(page.css("#fleet_counts .count").map(&:text)).to eq(%w[0 0 0 0 0 0])
    end

    context "with hosts" do
      let!(:media) { enrolled_host(name: "Media server", tags: %w[media]).first }
      let!(:pending) { create(:host, name: "Lab sandbox", tags: %w[lab]) }
      let!(:retired) { create(:host, :retired, name: "Retired box") }

      before do
        record_heartbeat(media)
        record_inventory(media)
      end

      it "lists every fleet column, with retired hosts neither listed nor counted" do
        # "Last seen" is relative to the clock, so render at the heartbeat's instant: a slow runner must not
        # turn "less than 5 seconds ago" into "less than 10 seconds ago" (#69).
        travel_to(media.reload.last_seen_at) { get "/" }
        row = page.at_css("tr#row_host_#{media.id}")
        # The hostname and tags are under the name (VT-SCORES #262, VT-D06), and Exposure and Work replace Open vulnerabilities.
        expect(row.css("td").map { |td| td.text.squish }).to eq(
          [ "Media server#{media.hostname}media", "Online", "less than 5 seconds ago", "Debian GNU/Linux 13 (trixie)",
            "Not evaluated: no rules are defined", "Not evaluated: no package report yet", "Not known", "0.1.0" ]
        )
        expect(row.at_css("td:first-child .host-line").text).to eq(media.hostname)
        expect(page.css("thead th").map { |th| th.text.squish }).to eq([ "Name", "Status", "Last seen", "Operating system", "CIS pass rate", "Exposure", "Work", "Agent" ])
        expect(row_names).to eq([ "Lab sandbox", "Media server" ])
        expect(response.body).not_to include("Retired box")
        expect(page.css("#fleet_counts .count").map(&:text)).to eq(%w[1 0 0 0 1 0])
      end

      it "marks a host whose agent is in recovery mode beside its status (#180)" do
        media.update_columns(agent_recovery_since: Time.current, agent_recovery_reason: "the agent kept failing")
        get "/"
        status = page.at_css("tr#row_host_#{media.id} td:nth-child(2)")
        expect(status.text.squish).to eq("OnlineRecovering")
        expect(status.at_css(".recovering")["title"]).to include("recovery mode")
        expect(page.css(".recovering").size).to eq(1)
      end

      it "marks unreported values as unavailable" do
        get "/"
        cells = page.css("tr#row_host_#{pending.id} td").map { |td| td.text.squish }
        expect(cells).to include("Pending enrollment", "Never", "Not reported", "—")
      end

      it "keeps search, filters, and sort in the URL and composes them" do
        get "/", params: { q: "server", tag: "media", status: "online", sort: "status", dir: "desc" }
        expect(row_names).to eq([ "Media server" ])
        expect(page.at_css("input[name=q]")["value"]).to eq("server")
        expect(page.at_css("select[name=tag] option[selected]").text).to eq("media")
        expect(page.at_css("select[name=status] option[selected]")["value"]).to eq("online")
        expect(page.at_css("input[name=sort]")["value"]).to eq("status")
        expect(page.at_css("th[aria-sort=descending]").text).to eq("Status")
        name_link = page.at_css("th a[href*='sort=name']")["href"]
        expect(Rack::Utils.parse_query(URI(name_link).query)).to eq("q" => "server", "tag" => "media", "status" => "online", "sort" => "name", "dir" => "asc")
      end

      it "explains when nothing matches, with a way back" do # not "vm-99": factory hostnames are vm-N, so that matched once the sequence passed 99
        get "/", params: { q: "no-such-host", tag: "media" }
        expect(page.at_css(".empty strong").text).to eq(%(No hosts match "no-such-host" with tag "media".))
        expect(page.at_css(".empty a")["href"]).to eq("/")
      end

      it "filters to the hosts without recovery mode, with a labelled select and plain wording (#232)" do
        get "/"
        select = page.at_css("label select[name=recovery]")
        expect(select.parent.text.squish).to start_with("Recovery mode")
        expect(select.css("option").map { |o| [ o["value"], o.text ] }).to eq([ [ "", "Any" ], %w[missing Not\ set\ up] ])
        expect(select.at_css("option[selected]")).to be_nil
        get "/", params: { recovery: "missing", sort: "status" }
        expect(row_names).to eq([ "Media server" ]) # it does not report recovery mode
        expect(page.at_css("select[name=recovery] option[selected]")["value"]).to eq("missing")
        expect(query(page.at_css("th a[href*='sort=name']"))).to include("recovery" => "missing")
        media.update_columns(agent_recovery_coverage: "set_up")
        get "/", params: { recovery: "missing", tag: "media" }
        expect(page.at_css(".empty strong").text).to eq(%(No hosts match tag "media" with recovery mode not set up.))
        # The filter alone, and every host covered: said as the good news it is (review of #235).
        get "/", params: { recovery: "missing" }
        expect(words(page.at_css("#all_recovery_set_up"))).to eq("Every active host that has sent a heartbeat has recovery mode set up. Show the whole fleet")
        expect(page.at_css("#all_recovery_set_up a")["href"]).to eq("/")
      end

      it "draws no pager when the fleet fits one page, as on the approved mockup" do
        get "/"
        expect(page.at_css("#fleet_pager")).to be_nil
      end

      it "pages a large fleet by keyset, keeping the search, filters, and sort in every link (#193)" do
        stub_const("FleetList::PER_PAGE", 1)
        get "/", params: { sort: "name", dir: "desc" }
        expect(row_names).to eq([ "Media server" ])
        expect(words(page.at_css("#fleet_pager"))).to eq("Previous 1 host shown of 2 Next")
        expect(query(page.at_css("#fleet_pager a[rel=next]"))).to eq("dir" => "desc", "after" => media.id.to_s)
        get "/", params: { sort: "name", dir: "desc", after: media.id }
        expect(row_names).to eq([ "Lab sandbox" ])
        expect(query(page.at_css("#fleet_pager a[rel=prev]"))).to eq("dir" => "desc", "before" => pending.id.to_s)
        expect(page.at_css("#fleet_pager span.off[aria-disabled=true]").text).to eq("Next")
        expect(page.css("thead a").map { |a| query(a).key?("after") }.uniq).to eq([ false ]) # a new sort starts at the first page
        get "/", params: { q: "a" }
        expect(words(page.at_css("#fleet_pager"))).to eq("Previous 1 host shown of 2 matching Next")
        get "/", params: { tag: "lab", after: pending.id }
        expect(words(page.at_css("#page_gone"))).to eq("No hosts are left on this page. The hosts it listed have changed or left these filters. Go to the first page")
        expect(query(page.at_css("#page_gone a"))).to eq("tag" => "lab")
      end

      it "links status counts to the filtered list" do
        get "/"
        expect(page.css("#fleet_counts a").map { |a| a["href"] }).to eq(%w[online stale offline awaiting pending revoked].map { |s| "/?status=#{s}" })
      end
    end

    # The compliance panel and the CIS pass rate and open vulnerabilities columns (P2-D05, owner decision Q8).
    context "with compliance results" do
      let!(:rules) { compliance_rules(2).values.flatten }
      let!(:media) { enrolled_host(name: "Media server").first }
      let!(:web) { enrolled_host(name: "Web A").first }
      let!(:backup) { enrolled_host(name: "Backup target").first }
      let!(:dns) { enrolled_host(name: "DNS resolver").first }
      let!(:pending) { create(:host, name: "Lab sandbox") }

      # Each cell's text with the link and the detail line apart; the screen-reader reason follows "Not evaluated" as it reads.
      def cells(host) = page.css("tr#row_host_#{host.id} td").map { |td| td.xpath(".//text()").map(&:text).join(" ").squish.gsub(" :", ":") }

      before do
        failing = %w[high-0 medium-0 low-0]
        cis_results!(media, rules.to_h { |r| [ r, failing.include?(r.key) ? "fail" : "pass" ] })
        cis_results!(web, rules.to_h { |r| [ r, r.key == "critical-0" ? "fail" : "pass" ] })
        cis_results!(backup, rules.to_h { |r| [ r, "pass" ] })
        [ media, web, backup ].each { |h| host_config!(h) && package_set!(h) && vulns_evaluated!(h) }
        findings!(media, "high", rule: "N4")
        findings!(media, "medium", fixed: "2.0-1", rule: "F1")
        findings!(web, "critical", rule: "L2")
        findings!(web, "low", "low", rule: "I2")
        findings!(dns, "high", state: "resolved")
      end

      it "sums up open CIS-aligned failures and vulnerability findings, linking to the Compliance view" do
        get "/"
        panel = page.at_css("#compliance_summary")
        expect(panel.at_css("a")["href"]).to eq("/compliance")
        expect(panel.at_css("p").text.squish).to eq(
          "4 open CIS-aligned check failures (1 critical, 1 high) on 3 of 4 hosts evaluated. 5 open vulnerability findings (1 critical, 1 high) on 3 of 4 hosts evaluated."
        )
        # VT-SCORES (#262, VT-D06): the same findings by bucket, with the work items, each linking to the Compliance page.
        expect(words(panel.at_css("#fleet_buckets"))).to eq("1 fix available (1 work item) · 1 needs attention · 1 low risk · 2 ignorable on 3 of 4 hosts evaluated.")
        expect(panel.css("#fleet_buckets a").map { |a| a["href"] }).to eq(%w[fix attention low_risk ignorable].map { |b| "/compliance?bucket=#{b}" })
      end

      it "shows each host's pass rate, exposure, and work, linked to its tabs; not evaluated and not tracked are words, never zero" do
        get "/"
        # VT-SCORES (#262): the tier, the points, and how many findings need attention; the work items and what they are.
        expect(cells(media)[4..6]).to eq([ "62.5% 3 failing, 1 high", "Exposed, no fix 24 points · 1 finding needs attention · not checked against KEV", "1 work item 1 upgrade" ])
        expect(cells(web)[4..6]).to eq([ "87.5% 1 failing, 1 critical", "Low 2 points · 0 need attention · not checked against KEV", "Nothing to install" ])
        expect(page.at_css("tr#row_host_#{media.id} .tier.t3")).not_to be_nil
        expect(cells(backup)[4..6]).to eq([ "100% None failing", "Minimal 0 points · 0 need attention · not checked against KEV", "Nothing to install" ])
        expect(cells(dns)[4..6]).to eq([ "Not evaluated: no config report yet", "Not evaluated: no inventory yet, so the distribution is not known", "Not known" ])
        expect(cells(pending)[4..6]).to eq([ "Not tracked", "Not tracked", "Not tracked" ])
        expect(page.at_css("tr#row_host_#{media.id} td:nth-child(5) a")["href"]).to eq("/hosts/#{media.id}/config#results")
        expect(page.at_css("tr#row_host_#{media.id} td:nth-child(6) a")["href"]).to eq("/hosts/#{media.id}/vulnerabilities#score")
        expect(page.at_css("tr#row_host_#{media.id} td:nth-child(7) a")["href"]).to eq("/hosts/#{media.id}/vulnerabilities#work")
        expect(page.css("tr#row_host_#{dns.id} .not-eval").size).to eq(3)
      end

      it "sorts by pass rate and by open vulnerabilities, with hosts that are not evaluated or not tracked last" do
        get "/", params: { sort: "cis" }
        expect(row_names).to eq([ "Media server", "Web A", "Backup target", "DNS resolver", "Lab sandbox" ])
        expect(page.at_css("th[aria-sort=ascending]").text).to eq("CIS pass rate")
        expect(page.at_css("caption").text).to eq("Hosts, CIS pass rate ascending")
        get "/", params: { sort: "cis", dir: "desc" }
        expect(row_names).to eq([ "Backup target", "Web A", "Media server", "DNS resolver", "Lab sandbox" ])
        get "/", params: { sort: "vulns", dir: "desc" }
        expect(row_names).to eq([ "Web A", "Media server", "Backup target", "DNS resolver", "Lab sandbox" ])
        expect(page.at_css("caption").text).to eq("Hosts, open vulnerabilities descending")
      end

      it "sorts by exposure (tier, then points) and by work, highest first only, with hosts not scored or not tracked last (VT-SCORES #262)" do
        get "/", params: { sort: "exposure", dir: "asc" } # one direction only
        expect(row_names).to eq([ "Media server", "Web A", "Backup target", "DNS resolver", "Lab sandbox" ])
        expect(page.at_css("th[aria-sort=descending]").text).to eq("Exposure")
        expect(page.at_css("caption").text).to eq("Hosts, highest exposure first: by tier, then points")
        expect(query(page.at_css("th a[href*='sort=exposure']"))).to eq("sort" => "exposure")
        get "/", params: { sort: "work" }
        expect(row_names).to eq([ "Media server", "Backup target", "Web A", "DNS resolver", "Lab sandbox" ])
        expect(page.at_css("caption").text).to eq("Hosts, most work first")
      end

      it "filters by vulnerabilities: known exploited, needs attention, a fix, nothing to install, not evaluated (VT-SCORES #262)" do
        findings!(web, "low", rule: "F1", kev: true)
        get "/"
        expect(page.at_css("label select[name=vulns]").css("option").map { |o| o["value"] }).to eq([ "", *FleetList::VULN_FILTERS.keys ])
        { "known_exploited" => [ "Web A" ], "attention" => [ "Media server" ], "fix" => [ "Media server", "Web A" ],
          "nothing_to_install" => [ "Backup target" ], "not_evaluated" => [ "DNS resolver" ] }.each do |filter, names|
          get "/", params: { vulns: filter }
          expect(row_names).to eq(names), filter
        end
        expect(query(page.at_css("th a[href*='sort=name']"))).to include("vulns" => "not_evaluated")
        get "/", params: { vulns: "known_exploited", q: "backup" }
        expect(page.at_css(".empty strong").text).to eq(%(No hosts match "backup" with vulnerabilities "Known exploited (not ignorable)".))
      end

      it "says when nothing is evaluated yet instead of counting zero" do
        CisResult.delete_all
        HostVulnerabilityEvaluation.delete_all
        VulnerabilityFinding.delete_all
        get "/"
        expect(page.at_css("#compliance_summary p").text.squish).to eq(
          "CIS-aligned checks are not evaluated on any of the 4 active hosts: none has a pass, fail, or not readable result. " \
          "Vulnerabilities are not evaluated on any of the 4 active hosts now."
        )
      end
    end

    it "shows no compliance panel without active hosts, and says when no rules are defined" do
      create(:host, name: "Lab sandbox")
      get "/"
      expect(page.at_css("#compliance_summary")).to be_nil
      enrolled_host
      get "/"
      expect(page.at_css("#compliance_summary p").text.squish).to start_with("CIS-aligned checks are not evaluated: no rules are defined.")
    end

    it "escapes operator- and agent-supplied text (P1-S12)" do
      host, = enrolled_host(name: HOSTILE, tags: %w[web])
      record_inventory(host, os: { "id" => "debian", "version_id" => "13", "pretty_name" => HOSTILE })
      get "/", params: { q: HOSTILE }
      expect(page.css("script:not([type])").map(&:text).grep(/alert/)).to eq([])
      expect(page.css("img[onerror]")).to be_empty
      expect(response.body.scan(%(&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;)).size).to be >= 2
    end

    it "opts into morphing page refreshes and keeps the live subscription across them (P1-D05)" do
      get "/"
      expect(page.at_css('meta[name="turbo-refresh-method"]')["content"]).to eq("morph")
      expect(page.at_css('meta[name="turbo-refresh-scroll"]')["content"]).to eq("preserve")
      source = page.at_css("turbo-cable-stream-source")
      expect(source["id"]).to eq("fleet_stream")
      expect(source["data-turbo-permanent"]).to eq("true")
    end

    it "runs a fixed number of queries whatever the fleet size, and renders 50 hosts in under 2 seconds" do
      3.times { |i| enrolled_host(tags: [ "t#{i}" ]).first.then { |h| record_heartbeat(h) && record_inventory(h) } }
      get "/" # warm up
      few = count_queries { get "/" }
      47.times { |i| enrolled_host(tags: [ "t#{i % 7}", "lab" ]).first.then { |h| record_heartbeat(h) && record_inventory(h) } }
      many = count_queries { get "/" }
      expect(many).to eq(few)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      get "/"
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      expect(row_names.size).to eq(50)
      expect(elapsed).to be < 2.0
    end
  end

  describe "GET /hosts/:id (host detail)" do
    let!(:enrolled) do
      host, token = Enrollment::RegisterHost.call({ name: "Media server", hostname: "vm-01.example.lan", tags: %w[media],
                                                    description: "Jellyfin and the download stack.", notes: "Line one\nLine two" },
                                                  actor: operator)
      Enrollment::Redeem.call(token:, machine_id: "0123456789abcdef0123456789abcdef", agent_version: "0.1.0", schema_version: 1)
      host.reload
    end
    let(:host) { enrolled }

    def section(heading) = page.xpath("//section[h2[normalize-space()='#{heading}']]").first

    def facts(heading) = section(heading).css("dt").to_h { |dt| [ dt.text, dt.next_element.text.squish ] }

    it "shows the current inventory, disks, and network (FR-1.3)" do
      record_heartbeat(host)
      record_inventory(host)
      get "/hosts/#{host.id}"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("Media server")
      expect(page.at_css("#status_host_#{host.id} .lamp").text).to eq("Online")
      expect(facts("Inventory")).to include(
        "Hostname" => "vm-01.example.lan", "Operating system" => "Debian GNU/Linux 13 (trixie) (debian 13)",
        "Kernel" => "6.12.0-example-amd64", "Architecture" => "x86_64", "CPU model" => "Example Virtual CPU", "CPU cores" => "4",
        "Total memory" => "8 GiB", "Available memory" => "6 GiB", "Uptime" => "1 day", "Boot ID" => "00000000-0000-4000-8000-0000000000b1",
        "Machine ID" => "0123456789abcdef0123456789abcdef", "Agent" => "0.1.0"
      )
      disks = section("Inventory").css("table").first.css("tbody tr").map { |tr| tr.css("td").map { |td| td.text.squish } }
      expect(disks).to eq([ [ "/", "ext4", "32 GiB", "20 GiB" ], [ "/srv/media files", "xfs", "1 TiB", "512 GiB" ] ])
      expect(section("Inventory").css(".meter span").map { |s| s["class"] }).to eq(%w[w-75 w-65 w-50]) # 62.5% rounds to the nearest 5% step
      network = section("Inventory").css("table").last.css("tbody tr").map { |tr| tr.css("td").map { |td| td.xpath(".//text()").map(&:text).join(" ").squish } }
      expect(network).to eq([ [ "ens18", "192.0.2.10/24 2001:db8::10/64", "Default route" ], [ "ens19", "198.51.100.10/24", "No" ] ])
      expect(response.body).not_to match(/style=/)
    end

    it "explains recovery mode, the agent's reason (escaped), and the next step (#180, ADR 0030)" do
      record_heartbeat(host)
      get "/hosts/#{host.id}"
      expect(page.at_css("#recovery_host_#{host.id}")).to be_nil
      expect(page.at_css(".recovering")).to be_nil
      since = Time.utc(2026, 11, 15, 9, 30)
      host.update_columns(agent_recovery_since: since, agent_recovery_retry_at: Time.utc(2026, 11, 15, 10, 30),
                          agent_recovery_reason: "a loop of the agent failed: <script>alert(1)</script>")
      get "/hosts/#{host.id}"
      expect(page.at_css("#status_host_#{host.id} .recovering").text).to eq("Recovering")
      notice = page.at_css("#recovery_host_#{host.id}")
      expect(notice.text.squish).to include(
        "The agent is in recovery mode.", "It kept failing on version 0.1.0", "Since 2026-11-15 09:30 UTC",
        "The agent says: a loop of the agent failed: <script>alert(1)</script>",
        "roll out a release newer than 0.1.0", "sudo systemctl start fleet-agent", "(next around 2026-11-15 10:30 UTC by the VM's clock)"
      )
      expect(notice.at_css("a")["href"]).to eq("/agents")
      expect(response.body).not_to include("<script>alert(1)</script>")
      expect(notice.css("script")).to be_empty

      # No retry time recorded: the hourly retry is still explained.
      host.update_columns(agent_recovery_retry_at: nil)
      get "/hosts/#{host.id}"
      expect(page.at_css("#recovery_host_#{host.id}").text.squish).to include("about once an hour.")

      # A host that is no longer active is not shown as recovering, whatever its last heartbeat said.
      host.revoke!(actor: operator)
      get "/hosts/#{host.id}"
      expect(page.at_css("#recovery_host_#{host.id}")).to be_nil
    end

    it "says whether recovery mode is set up, with the next step for each case (#232, review of #235)" do
      section = -> { page.at_css("#agent_updates #recovery_coverage_host_#{host.id}") }
      get "/hosts/#{host.id}"
      expect(section.call).to be_nil # no heartbeat yet
      record_heartbeat(host)
      get "/hosts/#{host.id}"
      # An old agent: update it first; its own installer would only write its old units again.
      expect(words(section.call)).to include("This agent does not report whether recovery mode is set up.", "Agent version 0.1.0 is older",
                                             "stops until someone starts it on the VM", "update the agent from Agents",
                                             "the next update installs them", "sudo fleet-agent install --refresh-units")
      expect(words(section.call)).not_to match(/sudo fleet-agent install(?! --refresh-units)/)
      expect(section.call["role"]).to eq("status")
      expect(section.call.at_css("a")["href"]).to eq("/agents")
      # Not set up: refresh the units on the VM, and what to do about a local copy.
      host.update_columns(agent_recovery_coverage: "not_set_up")
      get "/hosts/#{host.id}"
      expect(words(section.call)).to start_with("Recovery mode is not set up on this host.")
      expect(words(section.call)).to include("run sudo fleet-agent install --refresh-units", "restarts nothing",
                                             "a local copy: move it away", "sudo systemctl edit fleet-agent")
      expect(words(section.call)).not_to match(/sudo fleet-agent install(?! --refresh-units)/)
      # Not checked: its own text and next step, not "not set up" (re-review of #235).
      host.update_columns(agent_recovery_coverage: "unchecked")
      get "/hosts/#{host.id}"
      expect(words(section.call)).to start_with("Recovery mode could not be checked on this host.")
      expect(words(section.call)).to include("systemctl show failed or did not answer in time", "cannot tell whether recovery mode", "The next heartbeat checks again.")
      expect(words(section.call)).not_to include("--refresh-units")
      host.update_columns(agent_recovery_coverage: "set_up")
      get "/hosts/#{host.id}"
      expect(words(section.call)).to start_with("Recovery mode is set up.")
      expect(section.call["class"]).to be_nil
      host.revoke!(actor: operator)
      get "/hosts/#{host.id}"
      expect(section.call).to be_nil
    end

    it "shows unreadable facts as not available with the agent's warning" do
      record_inventory(host, name: "unreadable-facts")
      get "/hosts/#{host.id}"
      expect(facts("Inventory")["Machine ID"]).to eq("Not available/etc/machine-id: permission denied")
      expect(section("Inventory").at_css("p.unavailable").text).to eq("Not available/proc/self/mounts: read timed out after 5s")
    end

    it "shows each unreadable part of the CPU and memory on its own, with its warning (review of #53)" do
      record_inventory(host, cpu_model: nil, memory_available_bytes: nil,
                             warnings: [ { "field" => "cpu_model", "message" => "/proc/cpuinfo: no model name" },
                                         { "field" => "memory_available_bytes", "message" => "/proc/meminfo: MemAvailable missing" } ])
      get "/hosts/#{host.id}"
      expect(facts("Inventory")).to include("CPU model" => "Not available/proc/cpuinfo: no model name", "CPU cores" => "4",
                                            "Total memory" => "8 GiB", "Available memory" => "Not available/proc/meminfo: MemAvailable missing")

      record_inventory(host, memory_total_bytes: nil, warnings: [ { "field" => "memory_total_bytes", "message" => "/proc/meminfo: MemTotal missing" } ])
      get "/hosts/#{host.id}"
      expect(facts("Inventory")).to include("Total memory" => "Not available/proc/meminfo: MemTotal missing", "Available memory" => "6 GiB")
      available = section("Inventory").xpath(".//dt[.='Available memory']/following-sibling::dd[1]").first
      expect(available.css(".meter")).to be_empty # no meter without both values
    end

    it "shows notes as literal text with their line breaks, never as markup (review of #53)" do
      host.edit!({ notes: %(See <a href="https://example.com">the runbook</a> and <b>bold</b>\nSecond line <img src=x>) }, actor: operator)
      get "/hosts/#{host.id}"
      notes = section("Enrollment").at_css("dd.notes")
      expect(notes.css("a, b, img")).to be_empty
      expect(notes.css("br").size).to eq(1)
      expect(notes.text.squish).to eq(%(See <a href="https://example.com">the runbook</a> and <b>bold</b> Second line <img src=x>))
    end

    it "highlights the fields that changed in each snapshot, newest first (P1-D03)" do
      travel_to(2.days.ago) { record_inventory(host) }
      travel_to(1.day.ago) { record_inventory(host, kernel_version: "6.13.0-example-amd64", boot_id: "00000000-0000-4000-8000-0000000000b2") }
      record_inventory(host, kernel_version: "6.13.0-example-amd64", boot_id: "00000000-0000-4000-8000-0000000000b2", machine_id: nil)
      get "/hosts/#{host.id}"
      rows = section("Inventory history").css("tbody tr")
      expect(rows.size).to eq(3)
      changes = rows.first(2).map { |tr| tr.css("li").map { |li| li.text.squish } }
      expect(changes[0]).to eq([ "Machine ID 0123456789abcdef0123456789abcdef Not available" ])
      expect(changes[1]).to eq([ "Kernel 6.12.0-example-amd64 6.13.0-example-amd64", "Boot ID 00000000-0000-4000-8000-0000000000b1 00000000-0000-4000-8000-0000000000b2 (rebooted)" ])
      expect(rows[1].at_css("li del").text).to eq("6.12.0-example-amd64")
      expect(rows[1].at_css("li ins").text).to eq("6.13.0-example-amd64")
      expect(rows.last.css("td").last.text.squish).to eq("First inventory")
    end

    it "shows status history: when the host went offline and returned" do
      start = Time.current.change(usec: 0)
      travel_to(start - 30.minutes) { record_heartbeat(host) }
      Liveness.evaluate!(now: start - 25.minutes)
      Liveness.evaluate!(now: start - 10.minutes)
      travel_to(start) { record_heartbeat(host) }
      get "/hosts/#{host.id}"
      expect(section("Status history").css(".lamp").map(&:text)).to eq(%w[Online Offline Stale Online])
    end

    it "shows enrollment, credential, and the host's audit entries with their actors" do
      record_inventory(host)
      get "/hosts/#{host.id}"
      credential = host.agent_credentials.sole
      expect(facts("Enrollment")).to include("State" => "Active", "Credential" => "Active, key #{credential.key_id}",
                                             "Description" => "Jellyfin and the download stack.", "Notes" => "Line one Line two")
      expect(section("Enrollment").at_css("dd.notes br")).to be_present
      entries = section("Audit entries").css("td").map { |td| td.text.squish.sub(/, \d{4}-.*/, "") }
      expect(entries).to eq([ "First inventory receivedBy the host", "EnrolledBy the host", "Enrollment token issuedBy Example Operator", "Host createdBy Example Operator" ])
    end

    it "shows the newest credential when two have the same creation time (#69)" do
      token = Enrollment::IssueToken.call(host:, actor: operator)
      Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
      host.agent_credentials.update_all(created_at: Time.utc(2026, 10, 14, 10)) # a tie, as under a frozen test clock
      get "/hosts/#{host.id}"
      expect(facts("Enrollment")["Credential"]).to eq("Active, key #{host.agent_credentials.active.sole.key_id}")
    end

    it "shows a pending host's enrollment state and token expiry instead of liveness" do
      pending_host, = Enrollment::RegisterHost.call({ name: "Lab sandbox", hostname: "vm-06.example.lan" }, actor: Audit::SYSTEM)
      get "/hosts/#{pending_host.id}"
      expect(page.at_css(".host-head .lamp").text).to eq("Pending enrollment")
      expect(page.at_css(".host-head").text).not_to include("Last seen")
      expect(notice.at_css("strong").text).to eq("Pre-registered. Waiting for the installer to use its token.")
      expect(facts("Enrollment")).to include("State" => "Pending", "Credential" => "Never issued", "Token" => /\AExpires \d{4}-/)
      expect(section("Inventory").text).to include("No inventory yet.")
    end

    it "explains re-enrollment in progress, naming the credential still in use" do
      Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      get "/hosts/#{host.id}"
      expect(notice.at_css("strong").text).to eq("Re-enrollment in progress.")
      expect(notice.at_css("p").text).to include(host.agent_credentials.sole.key_id)
    end

    it "shows a revoked credential and a retired host" do
      host.revoke!(actor: Audit::SYSTEM)
      get "/hosts/#{host.id}"
      expect(page.at_css(".host-head .lamp").text).to eq("Credential revoked")
      expect(facts("Enrollment")["Credential"]).to match(/\ARevoked \d{4}-.*, key /)
      host.retire!(actor: Audit::SYSTEM)
      get "/hosts/#{host.id}"
      expect(notice.at_css("strong").text).to eq("This host is retired.")
    end

    it "warns when the credential is used from another machine (FR-S.1)" do
      record_inventory(host, machine_id: "fedcba9876543210fedcba9876543210")
      get "/hosts/#{host.id}"
      warning = notice
      expect(warning.at_css("strong").text).to eq("This credential was used from another machine.")
      expect(warning.css("code").map(&:text)).to eq(%w[0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210])
      expect(warning.at_css("p").text.squish).to end_with("If its agent config was copied to another VM, enroll that copy as a new host first. " \
                                                          "Then, or if you gave this VM a new machine ID, re-enroll this host to clear the warning.")
    end

    it "escapes hostile strings everywhere they appear (P1-D03)" do
      host.edit!({ name: HOSTILE, description: HOSTILE, notes: HOSTILE }, actor: operator)
      record_inventory(host, cpu_model: HOSTILE, kernel_version: HOSTILE,
                             disks: [ { "mount" => "/#{HOSTILE}", "filesystem" => HOSTILE, "size_bytes" => 10, "free_bytes" => 5 } ],
                             warnings: [ { "field" => "machine_id", "message" => HOSTILE } ], machine_id: nil)
      get "/hosts/#{host.id}"
      expect(page.css("script:not([type])").map(&:text).grep(/alert/)).to eq([])
      expect(page.css("img[onerror]")).to be_empty
      expect(page.at_css("h1").text).to eq(HOSTILE)
      expect(facts("Inventory")["CPU model"]).to eq(HOSTILE)
    end

    it "answers an unknown host with 404" do
      get "/hosts/0"
      expect(response).to have_http_status(:not_found)
    end
  end
end
