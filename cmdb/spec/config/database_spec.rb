require "rails_helper"

# The cable database (#194, reviews of #212 and #218): a connection attempt fails within 2 s, an error Solid Cable's
# listener retries, and no statement timeout, whose cancelled poll would stop the listener thread for good.
RSpec.describe "config/database.yml" do
  def cable(env) = ActiveRecord::Base.configurations.configs_for(env_name: env, name: "cable").configuration_hash

  it "gives the cable database a 2 s connect timeout and no statement timeout wherever it is a database" do
    %w[development production].each do |env|
      expect(cable(env)).to include(connect_timeout: 2), env
      expect(cable(env).fetch(:variables, {}).keys.map(&:to_s)).not_to include("statement_timeout"), env
    end
  end
end
