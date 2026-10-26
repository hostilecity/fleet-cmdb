# Operator tasks for hosts and enrollment before the dashboard exists (P1-S05). VM_HOSTNAME is used because
# shells set HOSTNAME to the local machine's name. Each prints the enrollment
# token once; it is not stored anywhere in plaintext. Changes are audited with the system actor.
namespace :hosts do
  desc "Create a pending host and print its enrollment token: DISPLAY_NAME=... VM_HOSTNAME=... [TAGS=web,lab] [DESCRIPTION=...]"
  task create: :environment do
    host, token = Enrollment::RegisterHost.call(
      { name: ENV.fetch("DISPLAY_NAME"), hostname: ENV.fetch("VM_HOSTNAME"), tags: ENV.fetch("TAGS", ""), description: ENV["DESCRIPTION"] },
      actor: Audit::SYSTEM
    )
    HostsTask.print_token(host, token)
  rescue KeyError => e
    abort "Missing #{e.key}. Usage: bin/rails hosts:create DISPLAY_NAME=... VM_HOSTNAME=... [TAGS=web,lab]"
  rescue ActiveRecord::RecordInvalid => e
    abort "Host not created: #{e.record.errors.full_messages.to_sentence}"
  end

  desc "Issue a new enrollment token for an existing host (re-enrollment): HOST_ID=... or VM_HOSTNAME=..."
  task enroll_token: :environment do
    host = HostsTask.find_host
    token = Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
    HostsTask.print_token(host.reload, token)
  rescue Enrollment::IssueToken::HostRetired
    abort "Host #{host.id} is retired and cannot be enrolled."
  end
end

module HostsTask
  module_function

  def find_host
    if ENV["HOST_ID"].present?
      Host.find_by(id: ENV["HOST_ID"]) || abort("No host with id #{ENV['HOST_ID']}.")
    elsif ENV["VM_HOSTNAME"].present?
      hostname = ENV["VM_HOSTNAME"].strip.downcase
      hosts = Host.in_fleet.where(hostname:).to_a
      abort "No host in the fleet has hostname #{hostname}." if hosts.empty?
      abort "Several hosts have hostname #{hostname}; use HOST_ID (#{hosts.map(&:id).join(', ')})." if hosts.size > 1
      hosts.first
    else
      abort "Set HOST_ID=... or VM_HOSTNAME=..."
    end
  end

  def print_token(host, token)
    expires = host.enrollment_tokens.order(:id).last.expires_at
    puts "Host #{host.id} (#{host.hostname}) is #{host.enrollment_state}."
    puts "Enrollment token (shown once, expires #{expires.utc.iso8601}):"
    puts token
    puts "On the VM: fleet-agent enroll --server https://<agent hostname> --token-stdin"
  end
end
