require "rails_helper"

# Credentials and tokens must never reach the logs (NFR-1). Later issues add more
# parameters; this guards the baseline configured at bootstrap.
RSpec.describe "Parameter filtering" do
  let(:filter) { ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters) }

  %w[
    authorization credential enrollment_token api_key bearer_token
    password session_id id_token recovery_code client_secret
  ].each do |name|
    it "filters #{name}" do
      expect(filter.filter(name => "value")[name]).to eq("[FILTERED]")
    end
  end

  it "leaves ordinary parameters alone" do
    expect(filter.filter("hostname" => "vm-01.example.lan")["hostname"]).to eq("vm-01.example.lan")
  end
end
