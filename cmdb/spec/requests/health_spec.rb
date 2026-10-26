require "rails_helper"

RSpec.describe "Application health", type: :request do
  it "boots and answers the Rails health check" do
    get "/up"

    expect(response).to have_http_status(:ok)
  end
end
