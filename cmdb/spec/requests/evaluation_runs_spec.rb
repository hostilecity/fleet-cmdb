require "rails_helper"

# The progress line of a fleet-wide evaluation run (#197; review of #204): a frame that refreshes only itself, backing
# off from 3 s to a minute, stopping when the run is done, failed, or stalled, and never counting as the operator's
# activity; and starting a failed run again.
RSpec.describe "Evaluation runs", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let!(:rule) { define_cis_rules(cis_rule_hash).first }
  def run = EvaluationRun.order(:id).last

  before { Array.new(3) { enrolled_host.first.tap { |h| record_inventory(h) && record_config(h) } } }

  def line(tick = nil)
    get "/evaluation-runs/#{run.id}/progress", params: { tick: }.compact
    expect(response).to have_http_status(:ok)
    expect(response.body).not_to include("<html") # the frame alone
    page.at_css("turbo-frame#evaluation_progress #evaluation_progress_text")
  end

  it "renders only the frame, asking for itself again after a delay that doubles up to a minute" do
    expect(line.text).to eq("Checking every host against the latest change: starting.")
    delays = [ nil, 1, 2, 3, 4, 5, 9, 100 ].map do |tick|
      node = line(tick)
      expect(node["data-evaluation-progress-url-value"]).to eq("/evaluation-runs/#{run.id}/progress?tick=#{tick.to_i + 1}") unless tick == 100
      node["data-evaluation-progress-seconds-value"].to_i
    end
    expect(delays).to eq([ 3, 6, 12, 24, 48, 60, 60, 3 ]) # a tick past 99 starts again
    perform_enqueued_jobs(only: EvaluationRunJob)
    expect(line.text).to eq("Checking every host against the latest change: 0 of 3 hosts done.")
  end

  it "reloads the page once when the run is done, and stops asking when it has not moved for 10 minutes" do
    perform_evaluation_jobs
    expect(line).to have_attributes(text: "Checking every host against the latest change: done.")
    expect(line["data-controller"]).to eq("refresh-after")
    expect(line["data-refresh-after-seconds-value"]).to eq("0")

    CisRule.transaction { rule.disable!(actor: operator) }
    travel(11.minutes)
    expect(line["data-controller"]).to be_nil
    expect(line.text.squish).to include("starting. No progress for 10 minutes: check that the job workers are running")
  end

  it "says a failed run stopped, with a button that starts it again, and stops asking" do
    perform_enqueued_jobs(only: EvaluationRunJob)
    EvaluationRun.fail!(run.id)
    node = line
    expect(node["data-controller"]).to be_nil
    expect(node.text.squish).to start_with("Stopped: 0 of 3 hosts done. Part of the work failed every retry")
    expect(node.at_css("form")["action"]).to eq("/evaluation-runs/#{run.id}/retry")

    get "/rules/#{rule.id}"
    expect(page.at_css("#evaluation_progress_text").text).to start_with("Stopped")

    failed = run
    expect { post "/evaluation-runs/#{failed.id}/retry" }.to change(EvaluationRun, :count).by(1)
    expect(response).to redirect_to("/rules/#{rule.id}")
    expect(flash[:notice]).to eq("Checking every host again.")
    perform_evaluation_jobs
    expect(failed.reload).to have_attributes(state: "superseded", superseded_by: run)
    get "/rules/#{rule.id}"
    expect(page.at_css("#evaluation_progress_text")).to be_nil

    post "/evaluation-runs/#{run.id}/retry" # finished: nothing to start
    expect(flash[:alert]).to eq("That run did not fail, so there is nothing to start again.")
  end

  it "starts a failed re-matching run again from Data sources" do
    advisories = EvaluationRun.create!(kind: "advisories", scope: { "packages" => { "Debian:13" => [ "curl" ] } }, state: "failed")
    get "/data-sources"
    expect(page.at_css("#evaluation_progress_text").text).to start_with("Stopped")
    post "/evaluation-runs/#{advisories.id}/retry"
    expect(response).to redirect_to("/data-sources")
    expect(flash[:notice]).to eq("Re-matching the affected hosts again.")
  end

  it "shows a re-triage on Data sources, and starts a failed one again there (VT-BUCKETS #259)" do
    partial = EvaluationRun.create!(kind: "triage", scope: { "reason" => "kev", "prepared" => true, "chunk_runs" => [ 1 ] }, state: "running")
    get "/evaluation-runs/#{partial.id}/progress"
    expect(page.at_css("#evaluation_progress_text").text).to start_with("Re-triaging the hosts whose findings' exploitation signals or Debian triage changed")
    partial.update!(state: "finished", finished_at: Time.current)
    triage = EvaluationRun.create!(kind: "triage", scope: { "reason" => "all" }, state: "failed")
    get "/data-sources"
    node = page.at_css("#evaluation_progress_text")
    expect(node.text).to start_with("Stopped")
    expect(node.at_css("button, input[type=submit]").then { |b| b.text.presence || b["value"] }).to eq("Re-triage again")
    triage.update!(state: "running")
    get "/evaluation-runs/#{triage.id}/progress"
    expect(page.at_css("#evaluation_progress_text").text).to start_with("Re-triaging every host's findings")
    triage.update!(state: "failed")
    post "/evaluation-runs/#{triage.id}/retry"
    expect(response).to redirect_to("/data-sources")
    expect(flash[:notice]).to eq("Re-triaging the affected hosts again.")
  end

  it "starts a failed run of several rules again from the first rule's page, or the rules list when it is gone" do
    several = EvaluationRun.create!(kind: "cis_rules", scope: { "rule_ids" => [ 0 ] }, state: "failed")
    post "/evaluation-runs/#{several.id}/retry"
    expect(response).to redirect_to("/rules")
  end

  it "does not count a refresh of the line as the operator's activity, so an open tab cannot keep the session alive" do
    session = OperatorSession.where(operator:).order(:id).last
    session.update_columns(last_seen_at: 1.hour.ago)
    expect { line }.not_to(change { session.reload.last_seen_at })
    expect { get "/rules/#{rule.id}" }.to(change { session.reload.last_seen_at })
  end
end
