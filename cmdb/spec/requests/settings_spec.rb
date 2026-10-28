require "rails_helper"

# The settings page (P1-D02, moved from P1-S09; FR-S.4).
RSpec.describe "Settings", type: :request do
  before do
    host! dashboard_host
    sign_in_operator
  end

  let(:operator) { Operator.find_by!(email: "operator@example.com") }

  def page = Nokogiri::HTML(response.body)

  it "shows the current thresholds" do
    get "/settings"
    expect(response).to have_http_status(:ok)
    expect(page.at_css("#online_minutes")["value"]).to eq("3")
    expect(page.at_css("#stale_minutes")["value"]).to eq("15")
  end

  it "changes the thresholds and audits the change against the operator" do
    expect { patch "/settings", params: { online_minutes: "5", stale_minutes: "20" } }.to change(AuditEntry, :count).by(2)
    expect(response).to redirect_to("/settings")
    expect(Setting.liveness_thresholds).to eq(online: 5.minutes, stale: 20.minutes)
    entries = AuditEntry.where(action: Audit::Actions::SETTING_CHANGED).chronological.last(2)
    expect(entries.map { |e| [ e.actor_type, e.actor_id ] }.uniq).to eq([ [ "operator", operator.id ] ])
    follow_redirect!
    expect(page.at_css(".flash").text.squish).to eq("Settings saved. They apply from the next liveness check.")
  end

  {
    "online not shorter than stale" => [ { online_minutes: "20", stale_minutes: "15" }, "online", "Must be shorter than the stale threshold (15 minutes)." ],
    "online not a number" => [ { online_minutes: "three", stale_minutes: "15" }, "online", "Enter a whole number of minutes." ],
    "stale missing" => [ { online_minutes: "3" }, "stale", "Enter a whole number of minutes." ],
    "stale out of range" => [ { online_minutes: "3", stale_minutes: "99999" }, "stale", "Must be between 2 and 10080 minutes." ]
  }.each do |name, (params, field, message)|
    it "rejects #{name} in place, keeping the values entered" do
      expect { patch "/settings", params: }.not_to change(AuditEntry, :count)
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css(".notice.error strong").text).to eq("Settings were not saved.")
      input = page.at_css("##{field}_minutes")
      expect(input["aria-invalid"]).to eq("true")
      expect(page.at_css("##{input['aria-describedby']}").text).to eq(message)
      expect(page.css("[aria-invalid]").size).to eq(1)
      expect(page.at_css("#online_minutes")["value"].to_s).to eq(params[:online_minutes].to_s)
      expect(Setting.liveness_thresholds).to eq(online: 3.minutes, stale: 15.minutes)
    end
  end

  it "requires the CSRF token outside tests" do
    ActionController::Base.allow_forgery_protection = true
    patch "/settings", params: { online_minutes: "5", stale_minutes: "20" }
    expect(response).to have_http_status(:unprocessable_content).or redirect_to(sign_in_path)
    expect(Setting.liveness_thresholds[:online]).to eq(3.minutes)
  ensure
    ActionController::Base.allow_forgery_protection = false
  end
end
