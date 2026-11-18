require "rails_helper"

# The rule for every action named with reads_from_replica (#198, re-review of #237): it must be safe to run twice,
# because a page whose replica fails part-way runs again on the primary (ReplicaReads.around). So the part that would run
# again (the action and its view, inside ReplicaReads.around) must only read: no write or row lock on any database (the
# queue's and cache's included, which the reading role does not guard), no job enqueued, no broadcast. This runs every
# such action and checks that, and fails when an action is named with reads_from_replica that this spec does not cover.
RSpec.describe "Pages that read the replica are safe to run twice", :signed_in, type: :request do
  WRITE = /\A\s*(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|CREATE|DROP|ALTER|LOCK)\b|\bFOR (NO KEY )?UPDATE\b|\bFOR (KEY )?SHARE\b|nextval\(/i

  let(:host) { enrolled_host.first }

  # "controller#action" => the path that runs it.
  def pages
    {
      "hosts#index" => "/",
      "compliance#index" => "/compliance",
      "audit_entries#index" => "/audit",
      "host_configs#show" => "/hosts/#{host.id}/config",
      "host_configs#compare" => "/hosts/#{host.id}/config/compare",
      "host_packages#show" => "/hosts/#{host.id}/packages",
      "host_packages#compare" => "/hosts/#{host.id}/packages/compare",
      "host_vulnerabilities#show" => "/hosts/#{host.id}/vulnerabilities",
      "host_vulnerabilities#package" => "/hosts/#{host.id}/vulnerabilities/package?package=#{VulnerabilityFinding.where(host:).pick(:package)}",
      "host_tasks#show" => "/hosts/#{host.id}/tasks"
    }
  end

  before do
    host_config!(host)
    package_set!(host)
    vulns_evaluated!(host)
    findings!(host, "high")
  end

  it "covers every action named with reads_from_replica" do
    Rails.autoloaders.main.eager_load_dir(Rails.root.join("app/controllers").to_s)
    expect(ReplicaReads::Controller.actions.to_a).to match_array(pages.keys)
  end

  it "has no write, lock, enqueue, or broadcast in the part a failing replica would run again" do
    side_effects = []
    record = lambda do |name, *, payload|
      if name == "sql.active_record"
        side_effects << payload[:sql] if payload[:sql].match?(WRITE)
      else
        side_effects << name
      end
    end
    inside = 0
    allow(ReplicaReads).to receive(:around).and_wrap_original do |original, **options, &block|
      original.call(**options) do
        inside += 1
        ActiveSupport::Notifications.subscribed(record, /\A(sql\.active_record|enqueue(_at)?\.active_job|broadcast\.action_cable)\z/, &block)
      end
    end

    pages.each do |action, path|
      side_effects.clear
      before = inside
      get path
      expect(response).to have_http_status(:ok), "#{action}: #{response.status}"
      expect(inside).to eq(before + 1), "#{action} did not read through ReplicaReads"
      expect(side_effects).to be_empty, "#{action} is not safe to run twice: #{side_effects.uniq.first(3).join(' | ')}"
    end
  end
end
