require "rails_helper"

# The settings page (P1-D02, moved from P1-S09; FR-S.4).
RSpec.describe "Settings", :signed_in, type: :request do
  it "shows the current thresholds" do
    get "/settings"
    expect(response).to have_http_status(:ok)
    expect(page.at_css("#online_minutes")["value"]).to eq("3")
    expect(page.at_css("#stale_minutes")["value"]).to eq("15")
  end

  describe "the server certificate (ADR 0024)" do
    def tls(days)
      key = OpenSSL::PKey::EC.generate("prime256v1")
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/O=CloudFlare, Inc./OU=CloudFlare Origin SSL ECC Certificate Authority")
      cert.public_key = key
      cert.not_before = 1.day.ago
      cert.not_after = days.days.from_now
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      cert.add_extension(factory.create_extension("subjectAltName", "DNS:agent.fleet.example.lan"))
      cert.sign(key, OpenSSL::Digest.new("SHA256"))
      ServerTls.new(cert.to_pem, key.to_pem)
    end

    around do |example|
      saved = Rails.configuration.x.server_tls
      example.run
    ensure
      Rails.configuration.x.server_tls = saved
    end

    it "shows what it is for, who issued it, and when it expires" do
      Rails.configuration.x.server_tls = tls(400)
      get "/settings"
      section = page.at_css("#server_certificate")
      expect(section.css("dd").map { |dd| dd.text.squish }.values_at(0, 1)).to eq([ "agent.fleet.example.lan", "CloudFlare Origin SSL ECC Certificate Authority" ])
      expect(section.css("dd")[2].text).to end_with("(in 399 days)")
      expect(section.at_css(".notice")).to be_nil
    end

    it "warns within 30 days of expiry, and once it has expired" do
      Rails.configuration.x.server_tls = tls(10)
      get "/settings"
      expect(page.at_css("#server_certificate .notice strong").text).to eq("The server's certificate expires in 9 days.")
      Rails.configuration.x.server_tls = tls(-1)
      get "/settings"
      expect(page.at_css("#server_certificate .notice strong").text).to eq("The server's certificate has expired.")
    end

    it "says when none is configured" do
      Rails.configuration.x.server_tls = nil
      get "/settings"
      expect(page.at_css("#server_certificate").text.squish).to include("No certificate is configured")
    end
  end

  it "changes the thresholds and audits the change against the operator" do
    expect { patch "/settings", params: { online_minutes: "5", stale_minutes: "20" } }.to change(AuditEntry, :count).by(2)
    expect(response).to redirect_to("/settings")
    expect(Setting.liveness_thresholds).to eq(online: 5.minutes, stale: 20.minutes)
    entries = AuditEntry.where(action: Audit::Actions::SETTING_CHANGED).chronological.last(2)
    expect(entries.map { |e| [ e.actor_type, e.actor_id ] }.uniq).to eq([ [ "operator", operator.id ] ])
    follow_redirect!
    expect(page.at_css(".flash").text.squish).to eq("Settings saved. They apply from the next liveness check.")
  end

  {
    "online not shorter than stale" => [ { online_minutes: "20", stale_minutes: "15" }, "online", "Must be shorter than the stale threshold (15 minutes)." ],
    "online not a number" => [ { online_minutes: "three", stale_minutes: "15" }, "online", "Enter a whole number of minutes." ],
    "stale missing" => [ { online_minutes: "3" }, "stale", "Enter a whole number of minutes." ],
    "stale out of range" => [ { online_minutes: "3", stale_minutes: "99999" }, "stale", "Must be between 2 and 10080 minutes." ]
  }.each do |name, (params, field, message)|
    it "rejects #{name} in place, keeping the values entered" do
      expect { patch "/settings", params: }.not_to change(AuditEntry, :count)
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css(".notice.error strong").text).to eq("Settings were not saved.")
      input = page.at_css("##{field}_minutes")
      expect(input["aria-invalid"]).to eq("true")
      expect(page.at_css("##{input['aria-describedby']}").text).to eq(message)
      expect(page.css("[aria-invalid]").size).to eq(1)
      expect(page.at_css("#online_minutes")["value"].to_s).to eq(params[:online_minutes].to_s)
      expect(Setting.liveness_thresholds).to eq(online: 3.minutes, stale: 15.minutes)
    end
  end

  it "requires the CSRF token outside tests" do
    ActionController::Base.allow_forgery_protection = true
    patch "/settings", params: { online_minutes: "5", stale_minutes: "20" }
    expect(response).to have_http_status(:unprocessable_content).or redirect_to(sign_in_path)
    expect(Setting.liveness_thresholds[:online]).to eq(3.minutes)
  ensure
    ActionController::Base.allow_forgery_protection = false
  end
end
