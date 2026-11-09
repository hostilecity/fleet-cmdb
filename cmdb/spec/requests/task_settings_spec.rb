require "rails_helper"

# Settings: Tasks (P3-S06, mockup settings-tasks.html): the allowlist, the protected services, and the limits. Every
# change needs a recent second factor, on the server, whatever page the request came from.
RSpec.describe "Settings: Tasks", type: :request do
  include_context "signed in operator"

  let(:secret) { @secret }

  before { @secret = enrol_second_factor(operator).first }

  def code = { second_factor_code: totp_code(secret) }

  it "starts with an empty allowlist that says so, the protected services, and the default limits" do
    get "/settings/tasks"
    expect(response).to have_http_status(:ok)
    expect(page.at_css("nav.tabs a[aria-current=page]").text).to eq("Tasks")
    expect(page.text).to include("No service can be restarted yet.")
    expect(page.css("tr.locked-row td.mono").map(&:text)).to include("ssh.service, sshd.service", "systemd-*.service")
    expect(page.at_css("#max_hosts_per_batch")["value"]).to eq("25")
    expect(page.at_css("#output_limit_kib")["value"]).to eq("64")
    expect(page.at_css("#poll_seconds")["value"]).to eq("30")
    expect(page.css("input[id^=expiry_]").map { |input| input["value"] }).to eq(%w[24 24 24])
    expect(page.text).to include("Time limits per task type (10, 5, and 60 minutes)")
    expect(page.css("input[name=second_factor_code]").map { |input| input["id"] }).to eq(%w[add_service_second_factor_code limits_second_factor_code])
  end

  it "adds a service with a code, lists it, and audits it" do
    create(:host, :active, tags: %w[web])
    get "/settings/tasks"
    expect(page.css("#tag option").map(&:text)).to eq([ "Every host", "Hosts tagged web" ])
    post "/settings/tasks/services", params: { service: "nginx.service", tag: "web", **code }
    expect(response).to redirect_to("/settings/tasks#allowlist")
    follow_redirect!
    expect(page.text).to include("Added nginx.service for hosts tagged web.")
    row = page.at_css("table.stack tbody tr")
    expect(row.css("td").map { |td| td.text.strip }.first(3)).to eq([ "nginx.service", "Hosts tagged web", "#{Time.current.utc.strftime('%Y-%m-%d')} by operator@example.com" ])
    expect(AuditEntry.where(action: Audit::Actions::TASK_SETTING_SERVICE_ADDED).sole.actor_id).to eq(operator.id)
  end

  it "refuses a forged change with no code: nothing changes, and the page shows the code box saying why" do
    post "/settings/tasks/services", params: { service: "nginx.service" }
    expect(response).to have_http_status(:forbidden)
    expect(TaskAllowedService.count).to eq(0)
    expect(page.at_css("#service")["value"]).to eq("nginx.service") # what was typed is kept
    patch "/settings/tasks/limits", params: { max_hosts_per_batch: "10", second_factor_code: "000000" }
    expect(response).to have_http_status(:forbidden)
    expect(page.at_css("#limits_second_factor_error").text).to include("That code was not accepted")
    expect(page.at_css("#add_service_second_factor_error")).to be_nil # only under the form it came from
    expect(page.at_css("#max_hosts_per_batch")["value"]).to eq("10")
    expect(TaskSettings.max_hosts_per_batch).to eq(25)
  end

  it "shows a refused service in place, as the mockup draws it" do
    post "/settings/tasks/services", params: { service: "ssh.service", **code }
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.at_css(".notice.error").text).to include("Not added: ssh.service is protected.")
    expect(page.at_css("#service_error").text).to include("never restarted remotely")
    post "/settings/tasks/services", params: { service: "nginx", tag: "Bad tag" }
    expect(page.at_css("#service_error").text).to start_with("Not a service unit name")
    expect(page.at_css("#tag_error").text).to eq("Choose every host or one tag.")
    expect(page.css("#tag option").map { |option| option["value"] }).to include("Bad tag") # what was chosen is kept
  end

  it "confirms a removal, naming the queued restarts that will be refused, then removes it with a code" do
    entry = TaskSettings.add_service!(service: "nginx.service", tag: nil, actor: operator)
    task = create_task(task_host, type: "restart_service", parameters: { "service" => "nginx.service" })
    get "/settings/tasks/services/#{entry.id}/remove"
    expect(page.at_css("h2").text).to eq("Remove nginx.service from the allowlist?")
    expect(page.text).to include("1 queued task that would restart it (batch #{task.task_batch_id}) will be refused")
    post "/settings/tasks/services/#{entry.id}/remove"
    expect(response).to have_http_status(:forbidden)
    expect(page.at_css("h2").text).to eq("Remove nginx.service from the allowlist?") # the confirmation again
    post "/settings/tasks/services/#{entry.id}/remove", params: code
    expect(response).to redirect_to("/settings/tasks#allowlist")
    expect(TaskAllowedService.count).to eq(0)
    post "/settings/tasks/services/#{entry.id}/remove"
    expect(flash[:alert]).to eq("That service is no longer on the list.")
  end

  it "saves limits with a code, says what changed, and shows errors in place" do
    patch "/settings/tasks/limits", params: { max_hosts_per_batch: "10", output_limit_kib: "64", poll_seconds: "30",
                                              expiry_hours: { restart_service: "12", refresh_reports: "24", apply_package_updates: "24" }, **code }
    expect(response).to redirect_to("/settings/tasks#limits")
    expect(flash[:notice]).to start_with("Limits saved. Most hosts in one batch: 25 → 10; Expiry of restart_service (hours): 24 → 12.")
    patch "/settings/tasks/limits", params: { max_hosts_per_batch: "10" }
    expect(flash[:notice]).to eq("Nothing changed.")
    patch "/settings/tasks/limits", params: { max_hosts_per_batch: "50", expiry_hours: { restart_service: "0" } }
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.at_css("#max_hosts_per_batch_error").text).to eq("At most 25. The cap cannot be raised from the dashboard.")
    expect(page.at_css("#expiry_restart_service_error").text).to include("from 1 to 168")
    expect(page.at_css("#expiry_restart_service")["value"]).to eq("0")
    expect(TaskSettings.max_hosts_per_batch).to eq(10)
  end

  it "shows the step-up as locked after too many wrong codes, with 429" do
    SecondFactors::MAX_FAILURES.times { patch "/settings/tasks/limits", params: { poll_seconds: "60", second_factor_code: "000000" } }
    expect(response).to have_http_status(:too_many_requests)
    expect(page.text).to include("Second factor locked until")
  end
end
