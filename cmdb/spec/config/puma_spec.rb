require "rails_helper"

# Puma refuses a request body over http_content_length_limit, chunked or not, before Rails sees it. The limit
# is the largest release upload, so an upload is never refused by Puma first, and nothing larger is ever
# buffered (review of #74).
RSpec.describe "config/puma.rb" do
  it "limits request bodies to the largest release upload" do
    puma = Rails.root.join("config/puma.rb").read
    expect(Integer(puma[/^http_content_length_limit (\S+)$/, 1].delete("_"))).to eq(AgentReleasesController::MAX_UPLOAD_BYTES)
  end
end
