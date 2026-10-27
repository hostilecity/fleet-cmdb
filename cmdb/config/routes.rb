Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  # Each route is constrained to its hostname (DEC-05, P1-S13). HostSeparation (lib/middleware) already
  # rejects wrong-host requests before routing; these constraints are the second line of defence.
  host = ->(request) { HostSeparation.normalize(request.host) }
  agent_host = ->(request) { host.(request) == HostSeparation.agent_host }
  dashboard_host = ->(request) { host.(request) == HostSeparation.dashboard_host }
  health_host = ->(request) { agent_host.(request) || HostSeparation::LOCAL_HOSTS.include?(host.(request)) }

  # Container and LAN health check: the agent host and localhost only, never the dashboard host (the tunnel).
  constraints(health_host) do
    get "up" => "rails/health#show", as: :rails_health_check
  end

  # Agent API (FR-S.2, docs/api), on the private agent hostname only. Keep the catch-all last so unknown
  # /api/v1 paths get the JSON error envelope.
  constraints(agent_host) do
    namespace :api do
      namespace :v1 do
        post "enroll", to: "enrollments#create"
        match "", to: "base#not_found", via: :all
        match "*path", to: "base#not_found", via: :all, format: false
      end
    end
  end

  # Dashboard, on the dashboard hostname only. Every controller requires a signed-in operator unless it opts
  # out (ApplicationController, P1-S01).
  constraints(dashboard_host) do
    root "dashboard#show"
    get "sign_in", to: "sessions#new", as: :sign_in
    get "auth/google_oauth2/callback", to: "sessions#create", as: :auth_callback
    get "auth/failure", to: "sessions#failure"
    delete "sign_out", to: "sessions#destroy", as: :sign_out
  end

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/")
  # root "posts#index"
end
