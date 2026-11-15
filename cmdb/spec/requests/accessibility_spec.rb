require "rails_helper"

# Keyboard use of the dashboard layout (UX assessment): the first thing a Tab reaches is a link past the top bar.
RSpec.describe "Dashboard layout accessibility", :signed_in, type: :request do
  it "starts every page with a skip link to the main content" do
    get "/"
    link = page.at_css("body a")
    expect(link.text).to eq("Skip to content")
    expect(link["href"]).to eq("#main")
    expect(page.at_css("main#main")["tabindex"]).to eq("-1")
  end
end
