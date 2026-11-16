require "rails_helper"

# Solid Cable's listener survives a short PostgreSQL restart (#194, review of #218): it retries a lost connection
# several times with growing pauses, not Solid Cable's default of once, at once.
RSpec.describe "config/cable.yml" do
  def cable(env) = ActiveSupport::ConfigurationFile.parse(Rails.root.join("config/cable.yml")).fetch(env)

  it "retries the listener's connection for about half a minute wherever the adapter is Solid Cable" do
    %w[development production].each do |env|
      expect(cable(env)).to include("adapter" => "solid_cable"), env
      attempts = cable(env).fetch("reconnect_attempts")
      expect(attempts).to eq([ 0, 1, 2, 5, 10 ]), env
      expect(SolidCable::Configuration.new(**cable(env).symbolize_keys).reconnect_attempts).to eq(attempts) # as Solid Cable reads it
    end
  end
end
