require "rails_helper"

# The fleet list and host detail pages (FR-1.5, P1-D02, P1-D03).
RSpec.describe "Hosts", type: :request do
  before do
    host! dashboard_host
    sign_in_operator
  end

  def page = Nokogiri::HTML(response.body)

  # Page notices, without the hidden live-update banner and the flash.
  def notice = page.at_css(".notice:not(.flash):not([data-live-status-target])")

  def row_names = page.css("tbody tr td:first-child a").map(&:text)

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
        expect(row.css("td").map { |td| td.text.squish }).to eq(
          [ "Media server", "Online", "less than 5 seconds ago", media.hostname, "media", "Debian GNU/Linux 13 (trixie)", "0.1.0" ]
        )
        expect(row_names).to eq([ "Lab sandbox", "Media server" ])
        expect(response.body).not_to include("Retired box")
        expect(page.css("#fleet_counts .count").map(&:text)).to eq(%w[1 0 0 0 1 0])
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

      it "explains when nothing matches, with a way back" do
        get "/", params: { q: "vm-99", tag: "media" }
        expect(page.at_css(".empty strong").text).to eq(%(No hosts match "vm-99" with tag "media".))
        expect(page.at_css(".empty a")["href"]).to eq("/")
      end

      it "links status counts to the filtered list" do
        get "/"
        expect(page.css("#fleet_counts a").map { |a| a["href"] }).to eq(%w[online stale offline awaiting pending revoked].map { |s| "/?status=#{s}" })
      end
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
    let(:operator) { Operator.find_by!(email: "operator@example.com") }

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
