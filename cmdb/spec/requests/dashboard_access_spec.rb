require "rails_helper"

# FR-S.4, P1-S01: no dashboard route is reachable without an allowlisted, signed-in operator.
RSpec.describe "Dashboard access", type: :request do
  # Routes that must work signed out: the sign-in page, the OAuth callback and failure, and sign-out.
  PUBLIC = %w[sessions#new sessions#create sessions#failure sessions#destroy].freeze

  def dashboard_routes
    Rails.application.routes.routes.filter_map do |route|
      controller, action = route.defaults.values_at(:controller, :action)
      next if controller.nil? || controller.start_with?("api/", "rails/")

      verb = route.verb.presence&.split("|")&.first || "GET"
      path = route.path.spec.to_s.sub("(.:format)", "").gsub(/[:*]\w+/, "1")
      { name: "#{controller}##{action}", verb: verb.downcase.to_sym, path: }
    end
  end

  it "finds the dashboard routes" do
    expect(dashboard_routes.pluck(:name)).to include("hosts#index", "hosts#show", "audit_entries#index", "settings#edit", "settings#update", *PUBLIC)
  end

  it "redirects anonymous requests for every non-public dashboard route to sign-in" do
    protected = dashboard_routes.reject { |route| PUBLIC.include?(route[:name]) }
    expect(protected).not_to be_empty
    protected.each do |route|
      public_send(route[:verb], route[:path])
      expect(response).to redirect_to(sign_in_path), "#{route[:verb].upcase} #{route[:path]} (#{route[:name]}) is reachable signed out"
    end
  end

  it "redirects an operator removed from the allowlist on every non-public dashboard route" do
    allow_operator("operator@example.com")
    sign_in_with_google
    OperatorAllowlistEntry.disallow!("operator@example.com", actor: Audit::SYSTEM)
    dashboard_routes.reject { |route| PUBLIC.include?(route[:name]) }.each do |route|
      public_send(route[:verb], route[:path])
      expect(response).to redirect_to(sign_in_path), "#{route[:name]} is reachable after removal from the allowlist"
    end
  end

  it "requires sign-in in every dashboard controller unless the action is explicitly public" do
    Rails.application.eager_load!
    (ApplicationController.descendants + [ ApplicationController ]).each do |controller|
      next if controller.abstract?

      controller.action_methods.each do |action|
        next if PUBLIC.include?("#{controller.controller_path}##{action}")

        callbacks = controller._process_action_callbacks.select { |cb| cb.kind == :before && cb.filter == :require_operator! }
        applies = callbacks.any? { |cb| cb.instance_variable_get(:@if).empty? && cb.instance_variable_get(:@unless).empty? }
        expect(applies).to be(true), "#{controller}##{action} does not require a signed-in operator"
      end
    end
  end

  it "has no sign-up, password, or operator-creation route, and no password column" do
    paths = Rails.application.routes.routes.map { |route| route.path.spec.to_s }
    expect(paths.grep(/sign_up|register|password|operators/)).to eq([])
    columns = ActiveRecord::Base.connection.tables.flat_map { |t| ActiveRecord::Base.connection.columns(t).map { |c| "#{t}.#{c.name}" } }
    expect(columns.grep(/passw/)).to eq([])
  end
end
