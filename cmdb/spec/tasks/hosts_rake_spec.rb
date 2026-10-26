require "rails_helper"
require "rake"

RSpec.describe "hosts rake tasks (P1-S05)" do
  before(:all) do
    Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "hosts:create" }
  end

  def run(task, env)
    Rake::Task[task].reenable
    original = env.keys.to_h { |key| [ key, ENV[key] ] }
    env.each { |key, value| ENV[key] = value }
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
    original.each { |key, value| ENV[key] = value }
  end

  it "creates a pending host and prints a working token once" do
    out = run("hosts:create", "DISPLAY_NAME" => "Media", "VM_HOSTNAME" => "media.example.lan", "TAGS" => "media, lab")
    host = Host.find_by!(hostname: "media.example.lan")
    expect(host).to have_attributes(enrollment_state: "pending", tags: %w[media lab])
    token = out.lines.map(&:strip).find { |line| EnrollmentToken::FORMAT.match?(line) }
    expect(EnrollmentToken.lock_for_redemption(token)).to have_attributes(host_id: host.id)
    expect(AuditEntry.for_target(host).pluck(:action)).to eq([ Audit::Actions::HOST_CREATED, Audit::Actions::HOST_ENROLLMENT_TOKEN_ISSUED ])
  end

  it "issues a re-enrollment token by hostname or id" do
    host, = enrolled_host(hostname: "web.example.lan")
    out = run("hosts:enroll_token", "VM_HOSTNAME" => "WEB.example.lan", "HOST_ID" => nil)
    expect(out).to include("is pending")
    expect(host.reload.enrollment_state).to eq("pending")
    run("hosts:enroll_token", "HOST_ID" => host.id.to_s, "VM_HOSTNAME" => nil)
    expect(host.enrollment_tokens.redeemable.count).to eq(1)
  end

  describe "errors" do
    def expect_abort(task, env, message)
      expect { expect { run(task, env) }.to output(/#{Regexp.escape(message)}/).to_stderr }.to raise_error(SystemExit)
    end

    it "explains missing or invalid arguments" do
      expect_abort("hosts:create", { "DISPLAY_NAME" => nil, "VM_HOSTNAME" => "x.example.lan" }, "Missing DISPLAY_NAME")
      expect_abort("hosts:create", { "DISPLAY_NAME" => "X", "VM_HOSTNAME" => "not a hostname" }, "Host not created: Hostname is invalid")
      expect_abort("hosts:enroll_token", { "HOST_ID" => nil, "VM_HOSTNAME" => nil }, "Set HOST_ID=... or VM_HOSTNAME=...")
      expect_abort("hosts:enroll_token", { "HOST_ID" => "0", "VM_HOSTNAME" => nil }, "No host with id 0")
    end

    it "refuses to enroll a retired host" do
      host = create(:host, :retired)
      expect_abort("hosts:enroll_token", { "HOST_ID" => host.id.to_s, "VM_HOSTNAME" => nil }, "is retired and cannot be enrolled")
    end
  end
end
