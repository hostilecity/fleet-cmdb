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
    # Monitoring: database, release files, and backup freshness (P1-S11, P1-O01).
    get "health" => "health#show", as: :health
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
        post "reports/packages", to: "package_reports#create"
        post "reports/config", to: "config_reports#create"
        get "manifest/config", to: "config_manifests#show"
        # Update outcomes (P1-UPDATES): exempt from the minimum version, like heartbeats and release downloads.
        post "update-results", to: "update_results#create"
        # Tasks (P3-S03, P3-S04): :id is the task's uuid; anything else falls through to not_found.
        post "tasks/poll", to: "tasks#poll"
        constraints(id: /\h{8}-\h{4}-\h{4}-\h{4}-\h{12}/) do
          post "tasks/:id/start", to: "tasks#start", format: false
          post "tasks/:id/progress", to: "tasks#progress", format: false
          post "tasks/:id/result", to: "tasks#result", format: false
        end
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
        # Not destructive, so no confirmation page; still a CSRF-protected POST (P2-S03).
        post :request_reports, to: "host_actions#request_reports"
        # Host tabs (P2-D02 to P2-D04): read-only pages; filters, sort, and the compared snapshots are in the URL.
        get :config, to: "host_configs#show"
        get "config/compare", to: "host_configs#compare", as: :compare_config
        get :packages, to: "host_packages#show"
        get "packages/compare", to: "host_packages#compare", as: :compare_packages
        get :vulnerabilities, to: "host_vulnerabilities#show"
        # The package name is a query parameter (?package=), as in the mockup, so no stored name can break a path.
        get "vulnerabilities/package", to: "host_vulnerabilities#package", as: :package_vulnerabilities
      end
    end
    # Fleet compliance (P2-D05): read-only; filters, sort, and page are in the URL.
    get "compliance", to: "compliance#index", as: :compliance
    # CIS-aligned rules (P2-D06). Adding and editing preview first (a POST that writes nothing), then save; enable and
    # disable are a confirmation page (GET) and a CSRF-protected POST. An uploaded rules file is previewed from a
    # short-lived copy (RuleImportPreview, owner decision Q13) named by a token, then applied or cancelled.
    resources :rules, only: %i[index show new create edit update], constraints: { id: /\d+/ } do
      collection do
        post :preview, to: "rules#preview_new", as: :preview_new
        get :import, to: "rule_imports#new"
        post :import, to: "rule_imports#create"
        get "import/:token", to: "rule_imports#show", as: :import_preview, constraints: { token: /[A-Za-z0-9_-]{1,64}/ }
        post "import/:token/apply", to: "rule_imports#apply", as: :apply_import, constraints: { token: /[A-Za-z0-9_-]{1,64}/ }
        delete "import/:token", to: "rule_imports#destroy", as: :cancel_import, constraints: { token: /[A-Za-z0-9_-]{1,64}/ }
      end
      member do
        post :preview, to: "rules#preview_edit", as: :preview_edit
        get :disable, to: "rules#confirm_disable"
        post :disable
        get :enable, to: "rules#confirm_enable"
        post :enable
        get "versions/:version", to: "rule_versions#show", as: :version, constraints: { version: /[1-9]\d{0,8}/ }
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
    # Your second factor (P3-S09, owner decision Q24): under Settings. Setting up shows a key once, after a fresh
    # Google sign-in; moving to a new phone and new recovery codes each ask for a code first. There is no route that
    # removes a second factor: a lost authenticator without recovery codes is reset from the console (ADR 0006).
    scope "settings/second-factor", controller: "second_factors" do
      get "", action: :show, as: :second_factor
      get "setup", action: :setup, as: :setup_second_factor
      post "setup", action: :enrol
      post "verify", action: :verify, as: :verify_second_factor
      get "recovery-codes/new", action: :new_recovery_codes, as: :new_recovery_codes
      post "recovery-codes", action: :create_recovery_codes, as: :recovery_codes
    end
    # Settings: Tasks (P3-S06, mockup settings-tasks.html): the restart allowlist and the task limits. Each change is a
    # CSRF-protected request that needs a recent second factor; removing a service has a confirmation page first.
    scope "settings/tasks", controller: "task_settings" do
      get "", action: :show, as: :task_settings
      post "services", action: :add_service, as: :task_setting_services
      get "services/:id/remove", action: :confirm_remove, as: :remove_task_setting_service, constraints: { id: /\d+/ }
      post "services/:id/remove", action: :remove_service, constraints: { id: /\d+/ }
      patch "limits", action: :update_limits, as: :task_setting_limits
    end
    # Cancelling (P3-S05): any operator, with a recent second factor (Q23). The dialogs and pages are P3-DASH-TASKS.
    post "tasks/:id/cancel", to: "task_cancellations#task", as: :cancel_task, constraints: { id: /\d+/ }
    post "tasks/batches/:id/cancel", to: "task_cancellations#batch", as: :cancel_task_batch, constraints: { id: /\d+/ }
    # Background jobs that failed every retry (P1-O02). Read-only; the layout banner links here.
    get "jobs/failed", to: "failed_jobs#index", as: :failed_jobs
    # Agent releases and installing (P1-RELEASES). Rollouts join this page with P1-UPDATES.
    get "agents", to: "agent_releases#index", as: :agents
    post "agents/releases/import", to: "agent_releases#import", as: :import_agent_release
    post "agents/releases/upload", to: "agent_releases#upload", as: :upload_agent_release
    get "agents/install", to: "agent_installs#show", as: :agent_install
    # Rollouts (P1-D09): each action is a confirmation page (GET) and a CSRF-protected POST to the Rollouts
    # service. Starting is confirmed too: the form on /agents asks for the confirmation page.
    resources :rollouts, path: "agents/rollouts", only: %i[new create] do
      member do
        %i[advance halt resume cancel].each do |action|
          get action, to: "rollouts#confirm_#{action}"
          post action
        end
      end
    end
    # Advisory data sources (P2-D06): refreshing is a confirmation page (GET) and a CSRF-protected POST, limited
    # by the cool-down (P2-S15); an upload is a CSRF-protected POST whose result has its own page.
    get "data-sources", to: "data_sources#show", as: :data_sources
    get "data-sources/refresh", to: "data_sources#confirm_refresh", as: :refresh_data_sources
    post "data-sources/refresh", to: "data_sources#refresh"
    post "data-sources/upload", to: "data_sources#upload", as: :upload_data_sources
    get "data-sources/imports/:id", to: "data_sources#import", as: :advisory_import, constraints: { id: /\d+/ }
    # A full import refused for what it would withdraw: the second confirmation, naming the counts (review of #129).
    post "data-sources/imports/:id/confirm-withdrawals", to: "data_sources#confirm_withdrawals", as: :confirm_withdrawals_advisory_import, constraints: { id: /\d+/ }
    patch "settings", to: "settings#update"
    # Live updates (P1-D05). Connections are authenticated (ApplicationCable::Connection).
    mount ActionCable.server => "/cable"
    get "sign_in", to: "sessions#new", as: :sign_in
    get "privacy", to: "pages#privacy", as: :privacy # public: Google's OAuth consent screen links to it
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
