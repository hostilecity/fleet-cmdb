require "rails_helper"

# The banner on every dashboard page when the history partitions' maintenance needs an operator (#195, review of #239):
# a warning on /health keeps it 200, so an uptime monitor does not see it; the banner does.
RSpec.describe "Maintenance banner", type: :request do
  describe "signed in", :signed_in do
    it "is not shown when nothing needs attention" do
      get "/"
      expect(page.at_css("#maintenance_banner")).to be_nil
    end

    it "lists what needs attention, escaped" do
      allow(Partitions).to receive(:attention).and_return([ Partitions::Problem.new(severity: :warning, text: "Inventory report ids: rows in the default <b>") ])
      get "/"
      banner = page.at_css("#maintenance_banner")
      expect(banner["class"]).to eq("notice")
      expect(banner.at_css("strong").text).to eq("Database maintenance needs attention.")
      expect(banner.css("li").map(&:text)).to eq([ "Inventory report ids: rows in the default <b>" ])
      expect(banner.text).to include('section "Partitions"')
    end

    it "says audited actions will fail, as an alert, when a problem is failing" do
      allow(Partitions).to receive(:attention).and_return([ Partitions::Problem.new(severity: :failing, text: "The audit log (audit_entries): 1 partitions created ahead, fewer than 2") ])
      get "/"
      banner = page.at_css("#maintenance_banner")
      expect(banner["class"]).to eq("notice error")
      expect(banner["role"]).to eq("alert")
      expect(banner.at_css("strong").text).to eq("Database maintenance needs attention now: audited actions will fail when the audit log's months run out.")
    end

    it "does not take the page down when the database cannot say" do
      allow(Partitions).to receive(:attention).and_raise(ActiveRecord::StatementInvalid, "boom")
      allow(Rails.logger).to receive(:error)
      get "/"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("#maintenance_banner")).to be_nil
      expect(Rails.logger).to have_received(:error).with("[partitions] maintenance status unavailable: ActiveRecord::StatementInvalid")
    end
  end
end
