require "rails_helper"

# The failed-jobs page and the banner that links to it (NFR-4, P1-O02).
RSpec.describe "Failed jobs", type: :request do
  describe "access" do
    it "is read-only: no route changes a failed job" do
      sign_in_operator
      %i[post put patch delete].each do |verb|
        public_send(verb, "/jobs/failed")
        expect(response).to have_http_status(:not_found), "#{verb.upcase} /jobs/failed"
      end
    end
  end

  describe "the list", :signed_in do
    it "says so when nothing has failed" do
      get "/jobs/failed"

      expect(response).to have_http_status(:ok)
      expect(page.at_css("title").text).to eq("Failed jobs · Fleet CMDB")
      expect(page.at_css("#no_failed_jobs")).to be_present
      expect(page.at_css("#failed_jobs_banner")).to be_nil
    end

    it "lists failed jobs newest first, with their error, escaping what the error says" do
      older = failed_job(class_name: "RetentionPruneJob", at: 2.hours.ago, error_class: "PG::ConnectionBad", message: "connection lost")
      newer = failed_job(class_name: "FleetBroadcastJob", queue: "low", at: 1.hour.ago, message: HOSTILE)

      get "/jobs/failed"

      rows = page.css("table.failed-jobs tbody tr")
      expect(rows.map { |row| row["id"] }).to eq([ "failed_job_#{newer.id}", "failed_job_#{older.id}" ])
      expect(rows.last.css("td").map { |td| td.text.squish }).to eq([ older.created_at.utc.strftime("%Y-%m-%d %H:%M UTC"), "RetentionPruneJob", "default", "PG::ConnectionBad connection lost" ])
      expect(page.css("main script, main img")).to be_empty
      expect(response.body).to include("&lt;script&gt;")
    end

    it "shows a long error shortened, and says when more failed than are listed" do
      stub_const("JobHealth::LIST_LIMIT", 1)
      failed_job(at: 2.hours.ago)
      failed_job(at: 1.hour.ago, message: "x" * 1_000)

      get "/jobs/failed"

      expect(page.css("table.failed-jobs tbody tr").size).to eq(1)
      expect(page.at_css("table.failed-jobs tbody tr td:last-child").text.size).to be < 400
      expect(page.at_css("#failed_jobs_truncated").text).to eq("Showing the newest 1 of 2 failed jobs.")
    end
  end

  describe "the banner", :signed_in do
    it "shows the number of recent failures on every page and links to the list" do
      failed_job
      failed_job(class_name: "OtherJob")

      get "/audit"

      banner = page.at_css("#failed_jobs_banner")
      expect(banner["role"]).to eq("alert")
      expect(banner.at_css("strong").text).to eq("2 background jobs failed recently.")
      expect(banner.at_css("a")["href"]).to eq("/jobs/failed")
    end

    it "says 'job' for one, and links to a page that lists it" do
      failed_job

      get "/"
      expect(page.at_css("#failed_jobs_banner strong").text).to eq("1 background job failed recently.")

      get page.at_css("#failed_jobs_banner a")["href"]
      expect(page.css("table.failed-jobs tbody tr").size).to eq(1)
    end

    it "is absent when there are no failures, or only old ones" do
      get "/"
      expect(page.at_css("#failed_jobs_banner")).to be_nil

      failed_job(at: 3.days.ago)
      get "/"
      expect(page.at_css("#failed_jobs_banner")).to be_nil
    end

    it "does not take the page down when the queue database cannot be read" do
      allow(JobHealth).to receive(:failing_count).and_raise(ActiveRecord::ConnectionNotEstablished)

      get "/"

      expect(response).to have_http_status(:ok)
      expect(page.at_css("#failed_jobs_banner")).to be_nil
    end

    it "is not shown to a signed-out visitor" do
      failed_job
      delete "/sign_out"

      get "/sign_in"

      expect(page.at_css("#failed_jobs_banner")).to be_nil
    end
  end
end
