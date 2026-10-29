require "rails_helper"

# Pre-register, edit, revoke, re-enroll, and retire (P1-D04, FR-1.1, FR-1.5, FR-S.1, FR-S.3, FR-S.4, AC-1.5).
RSpec.describe "Host actions", type: :request do
  before do
    host! dashboard_host
    sign_in_operator
  end

  let(:operator) { Operator.find_by!(email: "operator@example.com") }

  def page = Nokogiri::HTML(response.body)

  describe "pre-registering a host" do
    it "creates a pending host and shows its one-time token and install commands once" do
      get "/hosts/new"
      expect(page.at_css("form[data-turbo='false']")).to be_present # the token is in the POST response itself

      expect { post "/hosts", params: { host: { name: "Lab sandbox", hostname: "VM-06.example.lan.", tags: "Lab, ci", description: "Scratch" } } }
        .to change(Host, :count).by(1)
      expect(response).to have_http_status(:created)
      expect(response.headers["Cache-Control"]).to include("no-store")
      expect(page.at_css("head meta[name='turbo-cache-control']")["content"]).to eq("no-cache") # no Turbo snapshot for Back (review of #63)
      host = Host.last
      expect(host).to have_attributes(name: "Lab sandbox", hostname: "vm-06.example.lan", tags: %w[lab ci], enrollment_state: "pending")
      token = page.at_css("#enrollment_token").text
      expect(EnrollmentToken.where(token_digest: AgentApi.digest(token), host:)).to exist
      expect(page.css(".token").map(&:text)).to include("./fleet-agent install --server https://agent.fleet.example.lan --token-stdin")
      expect(page.at_css(".terminal").text).to include("FLEET_ENROLLMENT_TOKEN='#{token}'")
      expect(AuditEntry.for_target(host).pluck(:action, :actor_type)).to eq([ [ Audit::Actions::HOST_CREATED, "operator" ], [ Audit::Actions::HOST_ENROLLMENT_TOKEN_ISSUED, "operator" ] ])

      get "/hosts/#{host.id}"
      expect(response.body).not_to include(token) # never shown again
    end

    it "shows errors in place and keeps the input" do
      expect { post "/hosts", params: { host: { name: "Lab", hostname: "vm 06", tags: "lab, <b>" } } }.not_to change(Host, :count)
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css(".notice.error strong").text).to eq("The host was not pre-registered.")
      expect(page.css(".field.invalid input").map { |i| i["name"] }).to contain_exactly("host[hostname]", "host[tags]")
      expect(page.at_css("#host_hostname")["aria-describedby"]).to include("host_hostname_error")
      expect(page.at_css("#host_tags")["value"]).to eq("lab, <b>")
      expect(page.at_css("#host_name")["value"]).to eq("Lab")
    end
  end

  describe "editing" do
    let(:host) { create(:host, name: "Media server", tags: %w[media]) }

    it "saves changes and audits before and after values" do
      patch "/hosts/#{host.id}", params: { host: { name: "Media", hostname: host.hostname, tags: "media, lab", description: "Jellyfin", notes: "Line one" } }
      expect(response).to redirect_to("/hosts/#{host.id}")
      expect(host.reload).to have_attributes(name: "Media", tags: %w[media lab], notes: "Line one")
      entry = AuditEntry.for_target(host).where(action: Audit::Actions::HOST_EDITED).sole
      expect([ entry.actor_type, entry.actor_id ]).to eq([ "operator", operator.id ])
      expect(entry.changeset).to include("name" => [ "Media server", "Media" ], "tags" => [ %w[media], %w[media lab] ])
    end

    it "shows errors in place without saving" do
      patch "/hosts/#{host.id}", params: { host: { name: "", hostname: host.hostname, notes: "x" * 10_001 } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.css(".field.invalid textarea, .field.invalid input").map { |i| i["name"] }).to contain_exactly("host[name]", "host[notes]")
      expect(host.reload.name).to eq("Media server")
    end

    it "does not edit a retired host" do
      host.retire!(actor: Audit::SYSTEM)
      get "/hosts/#{host.id}/edit"
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "revoking" do
    let!(:enrolled) { enrolled_host(name: "Media server") }
    let(:host) { enrolled.first }

    it "asks first, then revokes so the agent's next request is refused (AC-1.5)" do
      get "/hosts/#{host.id}/revoke"
      expect(response).to have_http_status(:ok)
      expect(page.at_css(".dialog h2").text).to eq("Revoke the credential for Media server?")
      expect(host.reload.enrollment_state).to eq("active") # the GET changed nothing

      post "/hosts/#{host.id}/revoke"
      expect(response).to redirect_to("/hosts/#{host.id}")
      expect(host.reload.enrollment_state).to eq("revoked")
      expect(AgentCredential.authenticate("Bearer #{enrolled.last}")).to be_nil
      expect(AuditEntry.for_target(host).where(action: Audit::Actions::HOST_CREDENTIAL_REVOKED).pluck(:actor_type)).to eq([ "operator" ])
    end

    it "explains when there is no active credential to revoke" do
      host.revoke!(actor: Audit::SYSTEM)
      post "/hosts/#{host.id}/revoke"
      follow_redirect!
      expect(page.at_css(".flash").text.squish).to eq("Only an active host's credential can be revoked.")
    end
  end

  describe "retiring" do
    let(:host) { enrolled_host(name: "Media server", hostname: "vm-01.example.lan").first }

    it "requires the hostname typed exactly, then retires and leaves the fleet" do
      post "/hosts/#{host.id}/retire", params: { confirm_hostname: "vm-01" }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#confirm_hostname_error").text).to eq("Type vm-01.example.lan exactly to retire this host.")
      expect(host.reload.enrollment_state).to eq("active")

      post "/hosts/#{host.id}/retire", params: { confirm_hostname: " VM-01.example.lan " }
      expect(response).to redirect_to("/")
      expect(host.reload.enrollment_state).to eq("retired")
      expect(host.agent_credentials.active).to be_empty
      get "/hosts/#{host.id}"
      expect(page.css(".host-head .actions")).to be_empty # nothing left to act on
      get "/hosts/#{host.id}/retire"
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "re-enrolling" do
    let!(:enrolled) { enrolled_host(name: "Media server", hostname: "vm-01.example.lan") }
    let(:host) { enrolled.first }

    it "explains both ways, and issues a one-time token only on request" do
      get "/hosts/#{host.id}/reenroll"
      expect(page.at_css(".dialog").text).to include("fleet-agent install --reenroll", "Issue a one-time token")
      expect(host.reload.enrollment_state).to eq("active")

      post "/hosts/#{host.id}/reenroll"
      expect(response).to have_http_status(:ok)
      expect(response.headers["Cache-Control"]).to include("no-store")
      expect(page.at_css("head meta[name='turbo-cache-control']")["content"]).to eq("no-cache")
      token = page.at_css("#enrollment_token").text
      expect(host.reload.enrollment_state).to eq("pending")
      expect(AgentCredential.authenticate("Bearer #{enrolled.last}")).to be_present # works until the token is used
      Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
      expect(AgentCredential.authenticate("Bearer #{enrolled.last}")).to be_nil
    end
  end

  describe "the host page" do
    it "offers the actions that apply to the host's state" do
      active = enrolled_host.first
      get "/hosts/#{active.id}"
      expect(page.css(".host-head .actions a").map(&:text)).to eq([ "Edit", "Re-enroll", "Revoke credential", "Retire" ])
      pending = create(:host)
      get "/hosts/#{pending.id}"
      expect(page.css(".host-head .actions a").map(&:text)).to eq([ "Edit", "Re-enroll", "Retire" ])
    end
  end

  it "refuses every action without the CSRF token (FR-S.4)" do
    host = enrolled_host.first
    ActionController::Base.allow_forgery_protection = true
    post "/hosts/#{host.id}/revoke"
    post "/hosts/#{host.id}/retire", params: { confirm_hostname: host.hostname }
    expect(host.reload.enrollment_state).to eq("active")
  ensure
    ActionController::Base.allow_forgery_protection = false
  end
end
