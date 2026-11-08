require "rails_helper"

# The cool-down on the dashboard's "Refresh now" for the advisory feed (P2-S15, FR-2.4): refused with the time
# it is next allowed, nothing started or written but the audit entry; the schedule and the rake task are never
# refused but count as the last attempt; both outcomes audited with the operator. Concurrency is in
# manual_refresh_concurrency_spec.rb.
RSpec.describe Advisories::ManualRefresh do
  include ActiveJob::TestHelper

  let(:operator) { create(:operator) }
  let(:now) { Time.utc(2026, 11, 7, 8, 1, 0) }

  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:feed_url, :refresh_cooldown)
    config.feed_url = "https://advisories.example.org/osv/Debian/all.zip"
    config.refresh_cooldown = 300.seconds
    example.run
  ensure
    config.feed_url, config.refresh_cooldown = saved.values_at(:feed_url, :refresh_cooldown)
  end

  def request(at: now, as: operator) = described_class.request!(actor: as, now: at)

  def refresh_jobs = enqueued_jobs.select { |job| job["job_class"] == "AdvisoryFeedRefreshJob" }

  describe ".request!" do
    it "records a manual attempt, audits it with the operator, and enqueues the scheduled refresh job for it" do
      result = request
      attempt = AdvisoryRefreshAttempt.sole
      expect(result).to have_attributes(accepted?: true, refused?: false, attempt:, next_allowed_at: now + 5.minutes)
      expect(attempt).to have_attributes(kind: "manual", operator:, started_at: now)
      expect(AdvisoryFeedRefreshJob).to have_been_enqueued.once.with(attempt_id: attempt.id, triage: true)
      entry = AuditEntry.sole
      expect(entry).to have_attributes(action: "advisory.refresh_requested", actor_type: "operator", actor_id: operator.id, target_type: nil)
      expect(entry.changeset).to eq("source" => "advisories.example.org/osv/Debian/all.zip", "triage_source" => "security-tracker.debian.org/tracker/data/json",
                                    "next_allowed_at" => "2026-11-07T08:06:00Z")
    end

    it "refreshes Debian's triage right after, under the same cool-down and audit entry, unless the tracker is turned off (P2-D08, T2)" do
      expect(request).to have_attributes(accepted?: true, triage: true)
      saved = DebianTriage.config.tracker_url
      DebianTriage.config.tracker_url = nil
      later = request(at: now + 5.minutes)
      expect(later).to have_attributes(accepted?: true, triage: false)
      expect(AdvisoryFeedRefreshJob).to have_been_enqueued.once.with(attempt_id: later.attempt.id, triage: false)
      expect(AuditEntry.where(action: "advisory.refresh_requested").order(:id).last.changeset).to include("triage_source" => nil)
      expect(request(at: now + 6.minutes)).to have_attributes(refused?: true, triage: false) # the one cool-down covers both
    ensure
      DebianTriage.config.tracker_url = saved
    end

    it "refuses a second manual refresh within the cool-down with the time it is next allowed, audited, and starts nothing" do
      request
      clear_enqueued_jobs
      other = create(:operator)
      result = nil
      expect { result = request(at: now + 4.minutes, as: other) }.not_to(change { [ AdvisoryRefreshAttempt.count, AdvisoryImport.count ] })
      expect(result).to have_attributes(accepted?: false, refused?: true, attempt: nil, next_allowed_at: now + 5.minutes)
      expect(refresh_jobs).to be_empty
      entry = AuditEntry.order(:id).last
      expect(entry).to have_attributes(action: "advisory.refresh_refused", actor_type: "operator", actor_id: other.id, target_type: nil)
      expect(entry.changeset).to eq("next_allowed_at" => "2026-11-07T08:06:00Z")
    end

    it "accepts again once the cool-down has passed" do
      request
      expect(request(at: now + 5.minutes - 1.second)).to be_refused
      expect(request(at: now + 5.minutes)).to be_accepted
      expect(AdvisoryRefreshAttempt.count).to eq(2)
    end

    it "waits for the cool-down after a scheduled run or the rake task, which are never refused themselves" do
      request
      expect { described_class.record_start!(kind: "scheduled", now: now + 1.minute) }.to change(AdvisoryRefreshAttempt, :count).by(1)
      expect { described_class.record_start!(kind: "task", now: now + 2.minutes) }.to change(AdvisoryRefreshAttempt, :count).by(1)
      # The task started at 08:03, so the manual refresh the first one allowed at 08:06 now waits until 08:08.
      expect(request(at: now + 6.minutes)).to have_attributes(accepted?: false, next_allowed_at: now + 7.minutes)
      expect(request(at: now + 7.minutes)).to be_accepted
    end

    it "uses FLEET_ADVISORY_REFRESH_COOLDOWN" do
      Advisories.config.refresh_cooldown = 60.seconds
      request
      expect(request(at: now + 59.seconds)).to have_attributes(accepted?: false, next_allowed_at: now + 1.minute)
      expect(request(at: now + 60.seconds)).to be_accepted
    end

    it "records nothing when no feed is configured" do
      Advisories.config.feed_url = nil
      expect { request }.to raise_error(described_class::NotConfigured)
      expect([ AdvisoryRefreshAttempt.count, AuditEntry.count, refresh_jobs.size ]).to eq([ 0, 0, 0 ])
    end
  end

  describe ".next_allowed_at and .last_attempt (the dashboard button)" do
    it "is nil before any refresh, then the newest attempt's start plus the cool-down until it passes" do
      expect(described_class.next_allowed_at(now:)).to be_nil
      expect(described_class.last_attempt).to be_nil
      request
      scheduled = described_class.record_start!(kind: "scheduled", now: now + 2.minutes)
      expect(described_class.next_allowed_at(now: now + 3.minutes)).to eq(now + 7.minutes)
      expect(described_class.next_allowed_at(now: now + 7.minutes)).to be_nil
      expect(described_class.last_attempt).to eq(scheduled)
    end
  end

  describe ".record_start!" do
    it "is not for manual refreshes, which go through request!" do
      expect { described_class.record_start!(kind: "manual") }.to raise_error(ArgumentError)
    end
  end

  describe "the database" do
    # Each insert in a savepoint, so one refused statement does not abort the test's transaction.
    def insert(**row) = AdvisoryRefreshAttempt.transaction(requires_new: true) { AdvisoryRefreshAttempt.insert!({ started_at: now, **row }) }

    it "requires an operator for a manual attempt, and only for one" do
      expect { insert(kind: "manual") }.to raise_error(ActiveRecord::StatementInvalid, /operator_iff_manual/)
      expect { insert(kind: "scheduled", operator_id: operator.id) }.to raise_error(ActiveRecord::StatementInvalid, /operator_iff_manual/)
      expect { insert(kind: "button") }.to raise_error(ActiveRecord::StatementInvalid, /kind_valid/)
    end
  end

  describe "FLEET_ADVISORY_REFRESH_COOLDOWN" do
    def boot_with(value)
      saved = ENV.fetch("FLEET_ADVISORY_REFRESH_COOLDOWN", nil)
      ENV["FLEET_ADVISORY_REFRESH_COOLDOWN"] = value
      Advisories.config.delete(:refresh_cooldown)
      load Rails.root.join("config/initializers/advisories.rb")
      Advisories.config.refresh_cooldown
    ensure
      ENV["FLEET_ADVISORY_REFRESH_COOLDOWN"] = saved
    end

    it "is 300 seconds by default, including when set empty, and otherwise a whole number of seconds" do
      expect(boot_with(nil)).to eq(300.seconds)
      expect(boot_with("")).to eq(300.seconds)
      expect(boot_with("90")).to eq(90.seconds)
    end

    it "stops the server at boot, naming the setting, for anything but a whole number of at least 1" do
      [ "0", "-5", "5m", "1.5", "abc" ].each do |value|
        expect { boot_with(value) }.to raise_error(RuntimeError, "FLEET_ADVISORY_REFRESH_COOLDOWN must be a whole number of seconds, at least 1 (got #{value.inspect})")
      end
    end
  end
end
