require "rails_helper"

# The static error pages (public/*.html), as the approved mockup docs/mockups/phase-1/states.html shows them: what
# happened, that nothing was changed, and a way back to the fleet, in the dashboard's look (UX assessment).
RSpec.describe "Error pages", type: :request do
  after { ActionController::Base.allow_forgery_protection = false }

  it "explains a form sent without a valid CSRF token as an out-of-date page, and links back to the fleet" do
    sign_in_operator
    ActionController::Base.allow_forgery_protection = true
    # As in production: the public page, not the detailed exception page the test environment shows.
    allow(Rails.application).to receive(:env_config).and_wrap_original { |original| original.call.merge("action_dispatch.show_detailed_exceptions" => false) }
    patch "/settings", params: { liveness: { online_minutes: 3 } }
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.at_css("h1").text).to eq("Nothing was changed")
    expect(page.at_css("main").text.squish).to include("The page you sent this from was out of date.", "Go back, reload the page, and try again.")
    expect(page.at_css("main a")["href"]).to eq("/")
  end

  it "has a heading, a way back, and no script on every page" do
    %w[400 404 422 500].each do |code|
      html = Nokogiri::HTML(Rails.public_path.join("#{code}.html").read)
      expect(html.at_css("html")["lang"]).to eq("en"), code
      expect(html.css("h1").size).to eq(1), code
      expect(html.at_css("header a")["href"]).to eq("/"), code
      expect(html.css("script")).to be_empty, code
    end
  end
end
