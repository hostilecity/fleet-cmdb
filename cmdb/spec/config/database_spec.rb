require "rails_helper"

# The cable database fails a slow statement or connection within about 2 s (#194, follow-up to the review of #212),
# so a hung Solid Cable write fails a live-refresh flush, which its retry repeats, instead of holding a job thread.
RSpec.describe "config/database.yml" do
  def cable(env) = ActiveRecord::Base.configurations.configs_for(env_name: env, name: "cable").configuration_hash

  it "gives the cable database a 2 s statement and connect timeout wherever it is a database" do
    %w[development production].each do |env|
      expect(cable(env)).to include(connect_timeout: 2), env
      expect(cable(env)[:variables]).to include("statement_timeout" => 2000), env
    end
  end
end
