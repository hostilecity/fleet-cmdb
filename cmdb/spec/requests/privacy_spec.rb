require "rails_helper"

# The privacy page: public on the dashboard hostname (Google's OAuth consent screen links to it), linked from the
# sign-in page, and not served on the agent hostname.
RSpec.describe "Privacy page", type: :request do
  it "is readable without signing in, and the sign-in page links to it" do
    get privacy_path
    expect(response).to have_http_status(:ok)
    expect(page.at_css("h1").text).to eq("Privacy")
    expect(page.at_css("title").text).to eq("Privacy · Fleet CMDB")
    expect(page.at_css("article.privacy").text).to include("Your password stays with Google", "kept permanently", "never passwords")
    expect(page.at_css("article.privacy a[href='/']").text).to eq("Back to Fleet CMDB")

    get sign_in_path
    expect(page.at_css(".sign-in a[href='/privacy']").text).to eq("Privacy")
  end

  it "is the same page when signed in" do
    allow_operator("operator@example.com")
    sign_in_with_google
    get privacy_path
    expect(response).to have_http_status(:ok)
    expect(page.at_css("h1").text).to eq("Privacy")
  end

  it "is not served on the agent hostname" do
    host! Rails.configuration.x.fleet_hosts.agent
    get "/privacy"
    expect(response).to have_http_status(:not_found)
  end
end
