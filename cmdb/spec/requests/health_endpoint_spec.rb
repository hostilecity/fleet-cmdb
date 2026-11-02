require "rails_helper"

# /health (P1-S11, P1-O01, P1-O02): unauthenticated, minimal, and 503 when the database, the release files, the
# last backup, or the background jobs are not as they should be.
RSpec.describe "GET /health", type: :request do
  before do
    host! agent_host
    trust_release_keys
    FileUtils.touch(Rails.configuration.x.backup.status_file)
    liveness_job_ran
  end

  let(:all_ok) { { "database" => "ok", "releases" => "ok", "backup" => "ok", "failed_jobs" => "ok", "job_liveness" => "ok" } }

  it "is ok when everything is in place, and shows nothing else" do
    import_release(signed_release(version: "1.0.0"))

    get "/health"

    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to include("no-store")
    expect(response.parsed_body).to eq("status" => "ok", "checks" => all_ok)
  end

  it "is available on localhost for the container, and not on the dashboard hostname" do
    host! "localhost"
    get "/health"
    expect(response).to have_http_status(:ok)

    host! dashboard_host
    get "/health"
    expect(response).to have_http_status(:not_found)
  end

  it "is unhealthy when the newest release's binary is missing, without naming it" do
    release = import_release(signed_release(version: "1.0.0"))
    File.delete(release.binary_path)

    get "/health"

    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body).to eq("status" => "unhealthy", "checks" => all_ok.merge("releases" => "failing"))
    expect(response.body).not_to include("1.0.0")
  end

  it "is unhealthy when the newest release's binary has the wrong size" do
    release = import_release(signed_release(version: "1.0.0"))
    File.write(release.binary_path, "truncated")

    get "/health"

    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to include("releases" => "failing")
  end

  it "is unhealthy when no backup has been recorded, or the last one is too old" do
    File.delete(Rails.configuration.x.backup.status_file)
    get "/health"
    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to include("backup" => "failing")

    FileUtils.touch(Rails.configuration.x.backup.status_file, mtime: 3.days.ago.to_time)
    get "/health"
    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to include("backup" => "failing")
  end

  it "is unhealthy, and logs only the error class, when the database is unreachable" do
    allow(ActiveRecord::Base).to receive(:connection).and_raise(ActiveRecord::ConnectionNotEstablished, "secret detail")
    allow(Rails.logger).to receive(:error)

    get "/health"

    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to include("database" => "failing")
    expect(response.body).not_to include("secret detail")
    expect(Rails.logger).to have_received(:error).with("[health] a check raised ActiveRecord::ConnectionNotEstablished")
  end

  it "is unhealthy when the binary of a running rollout's target is missing, though it is not the newest release" do
    target = import_release(signed_release(version: "1.0.0"))
    canary, = host_running("0.1.0")
    rollout = start_rollout(release: target, canaries: [ canary ])
    import_release(signed_release(version: "1.1.0"))
    File.delete(target.binary_path)
    expect(rollout.reload.state).to eq("running")

    get "/health"

    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to eq(all_ok.merge("releases" => "failing"))
  end

  it "is unhealthy when a job failed all its retries recently, and says nothing about which" do
    failed_job(class_name: "SecretNamedJob", message: "private detail")

    get "/health"

    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to eq(all_ok.merge("failed_jobs" => "failing"))
    expect(response.body).not_to include("SecretNamedJob", "private detail")
  end

  it "ignores a failure older than the window, which stays on the failed-jobs page" do
    failed_job(at: (JobHealth::RECENT + 1.hour).ago)

    get "/health"

    expect(response).to have_http_status(:ok)
  end

  it "is unhealthy when the liveness job has not finished recently, or has never run" do
    SolidQueue::Job.delete_all
    get "/health"
    expect(response).to have_http_status(:service_unavailable)
    expect(response.parsed_body["checks"]).to eq(all_ok.merge("job_liveness" => "failing"))

    liveness_job_ran(at: (JobHealth::LIVENESS_MAX_AGE + 1.minute).ago)
    get "/health"
    expect(response).to have_http_status(:service_unavailable)

    liveness_job_ran(at: 30.seconds.ago)
    get "/health"
    expect(response).to have_http_status(:ok)
  end
end
