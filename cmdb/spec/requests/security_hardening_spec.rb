require "rails_helper"

# Server hardening (NFR-1, P1-S12): Content Security Policy, CSRF protection on every dashboard form and
# state-changing route, session cookie flags, and the production host allowlist. Escaping of hostile input is in
# hostile_input_spec.rb; parameter filtering of real log output is in structured_logging_spec.rb.
RSpec.describe "Security hardening", type: :request do
  def csp = response.headers["Content-Security-Policy"].to_s

  def directive(name) = csp.split(";").map(&:strip).find { |d| d.start_with?("#{name} ") }

  # The pages an operator can open, with whatever they need to exist. Used by the CSP and CSRF checks.
  def dashboard_pages
    host, = enrolled_host
    release_for_rollout
    request_record = start_onboarding(client_ip: "192.0.2.10").record
    [ "/", "/hosts/new", "/hosts/#{host.id}", "/hosts/#{host.id}/edit", "/hosts/#{host.id}/revoke", "/hosts/#{host.id}/retire",
      "/hosts/#{host.id}/reenroll", "/settings", "/audit", "/agents", "/agents/install", "/onboard", "/onboard/#{request_record.user_code}",
      "/jobs/failed" ]
  end

  describe "Content Security Policy" do
    it "is sent on the sign-in page and on every dashboard page" do
      get "/sign_in"
      expect(csp).to be_present

      sign_in_operator
      dashboard_pages.each do |path|
        get path
        expect(response).to have_http_status(:ok), "GET #{path}"
        expect(csp).to be_present, "no CSP on #{path}"
      end
    end

    it "allows scripts and styles from this site or with the request's nonce, and nothing from other origins" do
      get "/sign_in"

      nonce = csp[/script-src [^;]*'nonce-([^']+)'/, 1]
      expect(nonce).to be_present
      expect(directive("default-src")).to eq("default-src 'none'")
      expect(directive("script-src")).to eq("script-src 'self' 'nonce-#{nonce}'")
      expect(directive("style-src")).to eq("style-src 'self' 'nonce-#{nonce}'")
      expect(csp).not_to match(/unsafe-inline|unsafe-eval|\*|http:|data:.*script/)
      expect(directive("object-src")).to eq("object-src 'none'")
      expect(directive("frame-ancestors")).to eq("frame-ancestors 'none'")
      expect(directive("base-uri")).to eq("base-uri 'self'")
      expect(directive("form-action")).to eq("form-action 'self' https://accounts.google.com")
      expect(directive("connect-src")).to eq("connect-src 'self'")
      # The only origin other than this site is Google, for the sign-in form's redirect.
      expect(csp.scan(%r{https://[^\s;]+}).uniq).to eq([ "https://accounts.google.com" ])
    end

    it "uses a different nonce on each request" do
      nonces = Array.new(2) { get("/sign_in") && csp[/'nonce-([^']+)'/, 1] }
      expect(nonces.uniq.size).to eq(2)
    end

    it "gives every inline script and style in the page the nonce, and has no inline handlers or style attributes" do
      sign_in_operator
      dashboard_pages.each do |path|
        get path
        nonce = csp[/script-src [^;]*'nonce-([^']+)'/, 1]
        inline = page.css("script:not([src]), style")
        expect(inline).not_to be_empty
        expect(inline.map { |node| node["nonce"] }.uniq).to eq([ nonce ]), "inline code without the nonce on #{path}"
        expect(page.xpath("//@*[starts-with(name(), 'on')]")).to be_empty, "inline event handler on #{path}"
        expect(page.css("[style]")).to be_empty, "style attribute on #{path}"
        expect(page.css("script[src], link[href], img[src], iframe, object, embed, form[action]").flat_map { |node| node.attribute_nodes.map(&:value) }.grep(%r{\A(https?:)?//})).to be_empty, "external resource on #{path}"
      end
    end

    it "keeps Turbo and Stimulus loadable: the importmap pins only this site's own files" do
      get "/sign_in"

      importmap = JSON.parse(page.at_css('script[type="importmap"]').text)
      expect(importmap["imports"].keys).to include("@hotwired/turbo-rails", "@hotwired/stimulus", "application")
      expect(importmap["imports"].values).to all(start_with("/assets/"))
      expect(page.at_css('script[type="module"]').text).to include('import "application"')
    end
  end

  describe "CSRF protection" do
    # Tests run without forgery protection; switch it on once signed in (signing in is itself a token-less POST).
    after do
      ActionController::Base.allow_forgery_protection = false
      OmniAuth.config.test_mode = true
    end

    def enforce_csrf = (ActionController::Base.allow_forgery_protection = true)

    def state_changing_dashboard_routes
      Rails.application.routes.routes.filter_map do |route|
        controller = route.defaults[:controller]
        verb = route.verb.presence&.split("|")&.first
        next if controller.nil? || controller.start_with?("api/", "rails/") || controller == "health"
        next if verb.nil? || verb == "GET"

        { name: "#{controller}##{route.defaults[:action]}", verb: verb.downcase.to_sym, path: route.path.spec.to_s.sub("(.:format)", "").gsub(/[:*]\w+/, "1") }
      end
    end

    it "carries a token in every form the dashboard shows" do
      sign_in_operator
      enforce_csrf
      forms = 0
      dashboard_pages.each do |path|
        get path
        page.css("main form, header form").each do |form|
          forms += 1
          next if form["method"].casecmp?("get")

          expect(form.at_css('input[name="authenticity_token"]')).to be_present, "form #{form['action']} on #{path} has no CSRF token"
        end
      end
      expect(forms).to be > 5
    end

    it "refuses every state-changing dashboard route that arrives without a token, other than the OAuth and sign-out routes it explains" do
      sign_in_operator
      enforce_csrf
      routes = state_changing_dashboard_routes.reject { |route| route[:name].start_with?("sessions#") }
      expect(routes.pluck(:name)).to include("settings#update", "host_actions#retire", "approvals#approve", "agent_releases#import")
      routes.each do |route|
        public_send(route[:verb], route[:path])
        expect(response).to have_http_status(:unprocessable_content), "#{route[:verb].upcase} #{route[:path]} (#{route[:name]}) accepted a request without a CSRF token (got #{response.status})"
      end
    end

    it "starts the Google sign-in with a POST that needs a token (omniauth-rails_csrf_protection)" do
      enforce_csrf
      OmniAuth.config.test_mode = false
      get "/auth/google_oauth2"
      expect(response).to have_http_status(:not_found).or have_http_status(:method_not_allowed)
      post "/auth/google_oauth2"
      expect(response.location.to_s).not_to include("accounts.google.com")
    end
  end

  describe "the session cookie" do
    it "is HttpOnly and SameSite=Lax" do
      sign_in_operator

      cookie = response.headers["Set-Cookie"].to_s
      get "/"
      cookie = [ cookie, response.headers["Set-Cookie"].to_s ].join("\n")
      expect(cookie).to match(/_fleet_cmdb_session=/i)
      session_cookie = cookie.lines.find { |line| line.start_with?("_fleet_cmdb_session=") }
      expect(session_cookie).to match(/httponly/i)
      expect(session_cookie).to match(/samesite=lax/i)
    end

    it "is Secure in production, where every request is over TLS" do
      production = ActiveSupport::EnvironmentInquirer.new("production")
      allow(Rails).to receive(:env).and_return(production)
      load Rails.root.join("config/initializers/session_store.rb")
      expect(Rails.application.config.session_options).to include(key: "_fleet_cmdb_session", secure: true, httponly: true, same_site: :lax)
    ensure
      RSpec::Mocks.space.proxy_for(Rails).reset
      load Rails.root.join("config/initializers/session_store.rb")
    end

    it "is not Secure in development and test, where there is no TLS" do
      expect(Rails.application.config.session_options).to include(secure: false, httponly: true, same_site: :lax)
    end
  end

  describe "host allowlist" do
    it "answers a request for any other Host with an empty 404" do
      host! "evil.example.com"
      get "/sign_in"
      expect(response).to have_http_status(:not_found)
      expect(response.body).to be_empty
    end
  end
end
