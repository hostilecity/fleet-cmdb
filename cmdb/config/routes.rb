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
        post "onboarding", to: "onboardings#create"
        post "onboarding/token", to: "onboardings#token"
        post "heartbeat", to: "heartbeats#create"
        post "reports/inventory", to: "inventory_reports#create"
        # Release downloads (P1-S16): unauthenticated, limited per address, exempt from the minimum version.
        constraints(version: %r{[^/]+}) do
          get "releases/:version/manifest", to: "releases#manifest", format: false, as: :release_manifest
          get "releases/:version/signature", to: "releases#signature", format: false, as: :release_signature
          get "releases/:version/binary", to: "releases#binary", format: false, as: :release_binary
        end
        match "", to: "base#not_found", via: :all
        match "*path", to: "base#not_found", via: :all, format: false
      end
    end
  end

  # Dashboard, on the dashboard hostname only. Every controller requires a signed-in operator unless it opts
  # out (ApplicationController, P1-S01).
  constraints(dashboard_host) do
    root "hosts#index"
    resources :hosts, only: %i[show new create edit update] do
      # Each destructive action is a confirmation page (GET) and a CSRF-protected POST (FR-S.4, P1-D04).
      member do
        get :revoke, to: "host_actions#confirm_revoke"
        post :revoke, to: "host_actions#revoke"
        get :retire, to: "host_actions#confirm_retire"
        post :retire, to: "host_actions#retire"
        get :reenroll, to: "host_actions#confirm_reenroll"
        post :reenroll, to: "host_actions#reenroll"
      end
    end
    # Onboarding approval (P1-D07, DEC-17): the installer's verification URI is /onboard/<user code>.
    get "onboard", to: "approvals#index", as: :onboard
    post "onboard", to: "approvals#lookup"
    get "onboard/:code", to: "approvals#show", as: :onboard_request
    post "onboard/:code/approve", to: "approvals#approve", as: :approve_onboard_request
    post "onboard/:code/reject", to: "approvals#reject", as: :reject_onboard_request
    # The audit log is read-only (FR-S.3, P1-AUDIT-PAGE): no create, update, or destroy routes.
    get "audit", to: "audit_entries#index", as: :audit
    get "settings", to: "settings#edit", as: :settings
    # Agent releases and installing (P1-RELEASES). Rollouts join this page with P1-UPDATES.
    get "agents", to: "agent_releases#index", as: :agents
    post "agents/releases/import", to: "agent_releases#import", as: :import_agent_release
    post "agents/releases/upload", to: "agent_releases#upload", as: :upload_agent_release
    get "agents/install", to: "agent_installs#show", as: :agent_install
    patch "settings", to: "settings#update"
    # Live updates (P1-D05). Connections are authenticated (ApplicationCable::Connection).
    mount ActionCable.server => "/cable"
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
