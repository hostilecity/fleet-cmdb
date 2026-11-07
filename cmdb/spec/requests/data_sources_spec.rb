require "rails_helper"

# The Advisory data sources page (P2-D06, FR-2.4; approved mockups data-sources.html, data-sources-stale.html,
# data-sources-import.html, dialogs.html): freshness and counts per ecosystem, the scheduled feed without its
# token or query string, "Refresh now" with the cool-down of P2-S15 enforced by the server, uploading an advisory
# file with its result page, and every change audited with the operator as actor.
RSpec.describe "Advisory data sources", :signed_in, type: :request do
  include ActiveJob::TestHelper

  DATA_SOURCES_FEED = "https://feeds.example.lan/osv/Debian/all.zip".freeze

  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:feed_url, :feed_token, :refresh_cooldown)
    config.feed_url = DATA_SOURCES_FEED
    config.feed_token = nil
    config.refresh_cooldown = 300.seconds
    example.run
  ensure
    config.feed_url, config.feed_token, config.refresh_cooldown = saved.values_at(:feed_url, :feed_token, :refresh_cooldown)
  end

  def refreshed(at:, full: true, state: "succeeded", ecosystems: [ "Debian:13" ], origin: "feed", **attributes)
    AdvisoryImport.create!(origin:, source: "feeds.example.lan/osv/Debian/all.zip", full:, state:, ecosystems: (state == "failed" ? [] : ecosystems),
                           started_at: at, finished_at: at, **attributes)
  end

  def facts(scope = page) = scope.css("dt").map { |dt| dt.text.squish }.zip(scope.css("dd").map { |dd| dd.text.squish }).to_h

  def refresh_jobs = enqueued_jobs.select { |job| job["job_class"] == "AdvisoryFeedRefreshJob" }

  def upload(path, full: nil, confirm: nil, type: "application/zip")
    post "/data-sources/upload", params: { advisory_file: Rack::Test::UploadedFile.new(path.to_s, type), full:, confirm_full: confirm }.compact
  end

  describe "the page" do
    it "is in the main navigation as Data sources, marked as the current page" do
      get "/data-sources"
      expect(response).to have_http_status(:ok)
      expect(page.at_css('nav[aria-label="Main"] a[aria-current="page"]').text).to eq("Data sources")
      expect(page.at_css("h1").text).to eq("Advisory data sources")
    end

    it "shows freshness, current and withdrawn advisories, and hosts per ecosystem, counted in the database" do
      debian_host
      debian_host
      debian_host(os: { "id" => "ubuntu", "version_id" => "24.04", "name" => "Ubuntu" })
      import_advisories(osv_record(id: "DSA-9001-1"), osv_record(id: "DSA-9002-1", package: "curl"),
                        osv_record(id: "DSA-9003-1", withdrawn: "2026-10-21T00:00:00Z"), full: true)
      get "/data-sources"
      row = page.at_css("#ecosystems tbody tr").css("td").map { |cell| cell.css("span").map(&:text).presence&.join(" ") || cell.text.squish }
      expect(row[0]).to eq("Debian:13 Debian 13 (trixie)")
      expect(row[1]).to eq("Fresh")
      expect(page.at_css("#ecosystems tbody td:nth-child(4)").children.map { |node| node.text.strip }).to eq([ "2 current", "1 withdrawn" ])
      expect(row[4]).to eq("2 hosts")
      expect(page.at_css("#advisory_freshness").text.squish).to start_with("Advisory data last updated: Debian:13")
    end

    it "shows the feed's host and path only: never the token, never a query string" do
      Advisories.config.feed_url = "https://mirror:userinfo-secret@feeds.example.lan/osv/Debian/all.zip?key=query-secret-value&sig=another-secret"
      Advisories.config.feed_token = "token-secret-value"
      get "/data-sources"
      expect(facts(page.at_css("#feed_sheet dl"))).to include("Source" => "feeds.example.lan/osv/Debian/all.zip", "Access token" => "Configured, never shown",
                                                               "Stale after" => "48 hours")
      expect(response.body).not_to include("query-secret-value", "another-secret", "token-secret-value", "userinfo-secret", "key=")

      get "/data-sources/refresh"
      expect(page.at_css("#refresh_dialog").text).to include("(feeds.example.lan/osv/Debian/all.zip)")
      post "/data-sources/refresh"
      follow_redirect!
      [ "/data-sources", "/audit" ].each do |path|
        get path
        expect(response.body).not_to include("query-secret-value", "another-secret", "token-secret-value", "userinfo-secret"), path
      end
    end

    it "says when the feed has no token" do
      get "/data-sources"
      expect(facts(page.at_css("#feed_sheet dl"))).to include("Access token" => "None")
    end

    it "lists the recent imports with how, where from, the result, what happened, and who" do
      refreshed(at: 3.days.ago, state: "failed", reason: "could not download from the advisory feed at feeds.example.lan (ReadTimeout)")
      refreshed(at: 2.days.ago, counts: { "not_modified" => true })
      refreshed(at: 1.day.ago, operator:, counts: { "records" => 38_412, "created" => 6, "updated" => 22, "withdrawn" => 0, "absent" => 1, "malformed" => 0 })
      upload_import = refreshed(at: 1.hour.ago, origin: "file", full: false, operator:, source: "advisories-Debian-13.zip",
                                counts: { "records" => 312, "created" => 9, "updated" => 41, "malformed" => 2 })
      get "/data-sources"
      rows = page.css("#imports tbody tr").map { |row| row.css("td").map { |cell| cell.text.squish } }
      expect(rows.map { |row| row[1..] }).to eq([
        [ "File upload", "advisories-Debian-13.zip", "Succeeded", "312 records read: 310 imported, 2 malformed and skipped", "Example Operator" ],
        [ "Feed refresh", "feeds.example.lan/osv/Debian/all.zip", "Succeeded", "38,412 records read: 6 new, 22 changed, 1 withdrawn", "Example Operator" ],
        [ "Feed refresh", "feeds.example.lan/osv/Debian/all.zip", "Succeeded", "Not modified since the last download; nothing imported", "System" ],
        [ "Feed refresh", "feeds.example.lan/osv/Debian/all.zip", "Failed", "Nothing imported: could not download from the advisory feed at feeds.example.lan (ReadTimeout)", "System" ]
      ])
      expect(page.at_css("#imports a")["href"]).to eq("/data-sources/imports/#{upload_import.id}#skipped")
      expect(page.at_css(".pager").text.squish).to start_with("Showing the latest 4 imports.")
    end

    it "says when nothing has been imported yet" do
      get "/data-sources"
      expect(page.at_css("#no_imports").text.squish).to include("No advisory data has been imported yet.")
      expect(page.at_css("#ecosystems tbody td:nth-child(2)").text.squish).to eq("Never imported")
      expect(page.at_css("#advisory_freshness").text.squish).to include("Vulnerability data has never been refreshed.")
    end
  end

  # data-sources-stale.html: older than 48 hours and the refreshes failing.
  it "warns when the data is stale, with how many refreshes have failed since the last success" do
    last = refreshed(at: 3.days.ago)
    3.times { |i| refreshed(at: (2 - i).days.ago - 1.hour, state: "failed", reason: "the advisory feed at feeds.example.lan answered HTTP 503") }
    get "/data-sources"
    notice = page.at_css("#advisory_freshness")
    expect(notice["class"]).to eq("notice")
    expect(notice["role"]).to eq("alert")
    expect(notice.text.squish).to eq("Vulnerability data is out of date. Debian:13 advisory data was last updated 3 days ago (#{last.finished_at.utc.strftime('%Y-%m-%d %H:%M UTC')}), " \
                                     "so findings may be missing. The last 3 refreshes failed; see the imports below, or the failed jobs page.")
    expect(notice.at_css("a")["href"]).to eq("/jobs/failed")
    expect(page.at_css("#ecosystems tbody td:nth-child(2)").text.squish).to eq("Stale: older than 48 hours")
    expect(page.css("#imports .lamp.fail").size).to eq(3)
  end

  describe "Refresh now" do
    it "asks for confirmation, naming the feed, before anything starts" do
      get "/data-sources"
      expect(page.at_css("#refresh a")["href"]).to eq("/data-sources/refresh")
      get "/data-sources/refresh"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("#refresh_dialog h2").text).to eq("Refresh advisory data now?")
      expect(page.at_css("#refresh_dialog").text).to include("feeds.example.lan/osv/Debian/all.zip")
      expect(page.at_css("#refresh_dialog form")["method"]).to eq("post")
      expect(AdvisoryRefreshAttempt.count).to eq(0)
      expect(refresh_jobs).to be_empty
    end

    # AC (P2-D06): a second manual refresh within 5 minutes is refused by the server, and the button shows the time left.
    it "starts the refresh, audited with the operator, then disables the button with the time left, and the server refuses a second one" do
      freeze_time do
        post "/data-sources/refresh"
        expect(response).to redirect_to("/data-sources#feed")
        expect(flash[:notice]).to start_with("Refresh started.")
        attempt = AdvisoryRefreshAttempt.sole
        expect(attempt).to have_attributes(kind: "manual", operator:)
        expect(AdvisoryFeedRefreshJob).to have_been_enqueued.once.with(attempt_id: attempt.id)
        expect(AuditEntry.where(action: "advisory.refresh_requested").sole).to have_attributes(actor_type: "operator", actor_id: operator.id)

        travel 1.minute
        get "/data-sources"
        button = page.at_css("#refresh button")
        expect(button["disabled"]).to eq("disabled")
        expect(page.at_css("#refresh a")).to be_nil
        expect(page.at_css("#cool").text.squish).to eq("Available again in 4 minutes (last refresh #{attempt.started_at.utc.strftime('%Y-%m-%d %H:%M UTC')}).")
        # The button comes back by itself when the cool-down ends (refresh-after, as report requests do).
        expect(page.at_css("#refresh")["data-refresh-after-seconds-value"]).to eq("240")

        # A page drawn before the first refresh still offers the button; the server refuses.
        post "/data-sources/refresh"
        expect(response).to redirect_to("/data-sources#feed")
        follow_redirect!
        expect(page.at_css(".flash").text.squish).to eq("Refresh refused: a refresh started less than 5 minutes ago. It is available again at #{(attempt.started_at + 5.minutes).utc.strftime('%H:%M:%S UTC')}.")
        expect(AdvisoryRefreshAttempt.count).to eq(1)
        expect(refresh_jobs.size).to eq(1)
        refused = AuditEntry.where(action: "advisory.refresh_refused").sole
        expect(refused).to have_attributes(actor_type: "operator", actor_id: operator.id)
        expect(refused.changeset).to eq("next_allowed_at" => (attempt.started_at + 5.minutes).utc.iso8601)

        get "/data-sources/refresh"
        expect(response).to redirect_to("/data-sources#feed")

        travel 4.minutes + 1.second
        get "/data-sources"
        expect(page.at_css("#refresh a")["href"]).to eq("/data-sources/refresh")
      end
    end

    it "waits for the cool-down after a scheduled refresh too, and says less than a minute when that is what is left" do
      freeze_time do
        Advisories::ManualRefresh.record_start!(kind: "scheduled", now: 4.minutes.ago - 30.seconds)
        get "/data-sources"
        expect(page.at_css("#cool").text).to start_with("Available again in less than a minute")
      end
    end

    it "is not offered when no feed is configured, and the server refuses it, recording nothing" do
      Advisories.config.feed_url = nil
      get "/data-sources"
      expect(page.at_css("#feed_off").text.squish).to include("Automatic advisory refresh is off.", "only when you upload a file")
      expect(page.at_css("#refresh")).to be_nil
      expect(page.at_css("#advisory_freshness")["class"]).to eq("notice info")

      get "/data-sources/refresh"
      expect(response).to redirect_to("/data-sources")
      post "/data-sources/refresh"
      expect(response).to redirect_to("/data-sources")
      expect(flash[:alert]).to start_with("No advisory feed is configured on the server")
      expect(AdvisoryRefreshAttempt.count).to eq(0)
      expect(AuditEntry.where("action LIKE 'advisory.refresh%'")).to be_empty
    end

    it "refuses a request without a CSRF token" do
      ActionController::Base.allow_forgery_protection = true
      post "/data-sources/refresh"
      expect(response).to have_http_status(:unprocessable_content)
      expect(AdvisoryRefreshAttempt.count).to eq(0)
    ensure
      ActionController::Base.allow_forgery_protection = false
    end
  end

  describe "uploading an advisory file" do
    let(:valid) { osv_record(id: "DSA-9118-1", package: "openssl") }

    it "imports it, audited with the operator, and shows the result with the malformed records listed: where, which, and why" do
      debian_host(packages: [ [ "libssl3", "3.5.0-1", "openssl" ] ])
      zip = osv_zip("advisories/DSA-9118-1.json" => valid, "advisories/DSA-9119-1.json" => osv_record(id: "DSA-9119-1").merge("affected" => "nope"),
                    "advisories/broken.json" => '{"id": "DSA-9120-1", ')
      upload(zip)
      import = AdvisoryImport.sole
      expect(response).to redirect_to("/data-sources/imports/#{import.id}")
      expect(import).to have_attributes(origin: "file", source: "all.zip", full: false, operator:, state: "succeeded")
      expect(Advisory.pluck(:advisory_id)).to eq([ "DSA-9118-1" ])
      entry = AuditEntry.where(action: "advisory.imported").sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, target_type: "AdvisoryImport", target_id: import.id)

      follow_redirect!
      expect(page.at_css("h1").text).to eq("Import result")
      expect(page.at_css(".page-head p").text).to eq("File upload by Example Operator, #{import.finished_at.utc.strftime('%Y-%m-%d %H:%M UTC')}.")
      expect(page.at_css("#import_outcome strong").text).to eq("3 records read: 1 imported, 2 skipped.")
      expect(facts(page.at_css("dl.facts"))).to include("File" => "all.zip", "Type" => "Partial import (advisories not in the file are left alone)", "New" => "1",
                               "Changed" => "0", "Unchanged" => "0", "Withdrawn" => "0", "Skipped" => "2",
                               "Matching" => "Findings are being matched again for 1 package on 1 host.")
      rows = page.css("#skipped_records tbody tr").map { |row| row.css("td").map { |cell| cell.text.squish } }
      expect(rows.size).to eq(2)
      expect(rows.map(&:first)).to contain_exactly("all.zip / advisories/DSA-9119-1.json", "all.zip / advisories/broken.json")
      expect(rows.find { |row| row.first.end_with?("DSA-9119-1.json") }[1]).to eq("DSA-9119-1")
      expect(rows.find { |row| row.first.end_with?("broken.json") }[1]).to eq("No valid id")
      expect(rows.map(&:last)).to all(be_present)

      # The matching line is for the page right after the upload; the import does not store it.
      get "/data-sources/imports/#{import.id}"
      expect(page.css("dl.facts dt").map(&:text)).not_to include("Matching")

      get "/data-sources"
      expect(page.at_css("#imports tbody tr").text.squish).to include("File upload", "all.zip", "3 records read: 1 imported, 2 malformed and skipped", "Example Operator")

      # The audit log links the import to its result.
      get "/audit"
      expect(page.css("a").map { |a| a["href"] }).to include("/data-sources/imports/#{import.id}")
    end

    it "imports a single .json record" do
      upload(AdvisoryHelpers::OSV_FIXTURES.join("DSA-9001-1.json"), type: "application/json")
      expect(AdvisoryImport.sole).to have_attributes(source: "DSA-9001-1.json", state: "succeeded")
      follow_redirect!
      expect(page.at_css("#import_outcome strong").text).to eq("1 record read: 1 imported.")
    end

    it "imports nothing from a file it cannot read, and says so, audited with the operator" do
      bad = Pathname(Dir.mktmpdir("osv-bad-")).join("advisories-Debian-13.zip")
      @osv_dirs = [ *@osv_dirs, bad.dirname ]
      bad.binwrite("PK\x03\x04 this is not really a zip archive")
      upload(bad)
      import = AdvisoryImport.sole
      expect(import).to have_attributes(state: "failed", operator:, source: "advisories-Debian-13.zip", reason: "advisories-Debian-13.zip is not a readable zip archive")
      expect(Advisory.count).to eq(0)
      expect(AuditEntry.where(action: "advisory.import_failed").sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
      follow_redirect!
      outcome = page.at_css("#import_outcome")
      expect(outcome["class"]).to eq("notice error")
      expect(outcome.text.squish).to eq("Nothing was imported. advisories-Debian-13.zip is not a readable zip archive. A file that cannot be read at all, " \
                                        "or that breaks a size limit, imports nothing. Check the download and upload it again.")
    end

    it "asks for confirmation before a full import, which the server requires, and then withdraws what the file lacks" do
      import_advisories(osv_record(id: "DSA-9001-1"), osv_record(id: "DSA-9002-1"), full: true)
      zip = osv_zip("DSA-9001-1.json" => osv_record(id: "DSA-9001-1", modified: "2026-10-22T08:00:00Z"))

      get "/data-sources"
      form = page.at_css("#upload_form")
      expect(form["data-controller"]).to eq("confirm-full")
      expect(form.at_css("dialog#full_dialog h2").text).to eq("Import as a full import?")
      expect(form.css("dialog button").map(&:text)).to eq([ "Import as full", "Import without withdrawing" ])

      upload(zip, full: "1")
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#full_error").text).to eq("Confirm the full import, or clear Full import to import without withdrawing.")
      expect(page.at_css("#full")["checked"]).to eq("checked")
      expect(AdvisoryImport.count).to eq(1)

      upload(zip, full: "1", confirm: "1")
      import = AdvisoryImport.order(:id).last
      expect(import).to have_attributes(full: true, operator:)
      expect(Advisory.find_by(advisory_id: "DSA-9002-1").withdrawn_reason).to eq("absent")
      follow_redirect!
      expect(page.css("dl.facts dd").map { |dd| dd.text.squish }).to include("Full import (advisories of its ecosystems that are not in the file are marked withdrawn)",
                                                                             "1 (1 because the full import did not contain them)")
    end

    it "refuses no file, another kind of file, and a body over the limit, importing nothing" do
      post "/data-sources/upload", params: {}
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#advisory_file_error").text).to eq("Choose an advisory file to upload.")
      expect(page.at_css("#advisory_file")["aria-invalid"]).to eq("true")

      other = Pathname(Dir.mktmpdir("osv-other-")).join("advisories.tar")
      @osv_dirs = [ *@osv_dirs, other.dirname ]
      other.write("x")
      upload(other, type: "application/x-tar")
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#advisory_file_error").text).to eq("Upload an OSV .json file or a .zip archive of them.")

      post "/data-sources/upload", headers: { "CONTENT_LENGTH" => (DataSourcesController::MAX_BODY_BYTES + 1).to_s }
      expect(response).to have_http_status(:content_too_large)
      expect(AdvisoryImport.count).to eq(0)
    end

    it "refuses a file over the limit with the way to import a larger one" do
      stub_const("DataSourcesController::MAX_UPLOAD_BYTES", 10)
      upload(AdvisoryHelpers::OSV_FIXTURES.join("DSA-9001-1.json"), type: "application/json")
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#advisory_file_error").text).to include("bin/rails advisories:import")
      expect(AdvisoryImport.count).to eq(0)
    end

    it "keeps only the file's own name, never a client's path" do
      file = Rack::Test::UploadedFile.new(AdvisoryHelpers::OSV_FIXTURES.join("DSA-9001-1.json").to_s, "application/json", original_filename: "C:\\Users\\op\\Downloads\\DSA-9001-1.json")
      post "/data-sources/upload", params: { advisory_file: file }
      expect(AdvisoryImport.sole.source).to eq("DSA-9001-1.json")
    end

    it "refuses a request without a CSRF token" do
      ActionController::Base.allow_forgery_protection = true
      upload(AdvisoryHelpers::OSV_FIXTURES.join("DSA-9001-1.json"), type: "application/json")
      expect(response).to have_http_status(:unprocessable_content)
      expect(AdvisoryImport.count).to eq(0)
    ensure
      ActionController::Base.allow_forgery_protection = false
    end
  end

  it "links the fleet list's stale warning to this page" do
    get "/"
    expect(page.at_css("#advisory_freshness a")["href"]).to eq("/data-sources")
  end
end
