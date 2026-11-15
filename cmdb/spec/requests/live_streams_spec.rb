require "rails_helper"

# Which live-refresh streams each dashboard page listens to (#194): a host's pages listen to that host, not to the
# whole fleet, so an open host page does not refresh when another host or another host's task changes.
RSpec.describe "Live refresh streams", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let(:media) { task_host(name: "Media server") }
  let(:web) { task_host(name: "Web A") }

  def streams_of(path)
    get path
    expect(response).to have_http_status(:ok)
    page_streams(page)
  end

  def host_streams(host) = [ FleetBroadcast.host_stream(host.id), FleetBroadcast::ALL_HOSTS_STREAM ]

  # The refreshes the given streams got when the pending ones were sent.
  def refreshes_to(streams)
    ActionCable.server.pubsub.clear
    perform_enqueued_jobs
    streams.sum { |stream| ActionCable.server.pubsub.broadcasts(stream).size }
  end

  it "gives every tab of a host, and its task pages, that host's stream and the all-hosts stream only" do
    task = create_task(media)
    %W[/hosts/#{media.id} /hosts/#{media.id}/packages /hosts/#{media.id}/config /hosts/#{media.id}/vulnerabilities
       /hosts/#{media.id}/tasks /tasks/#{task.id}].each do |path|
      expect(streams_of(path)).to eq(host_streams(media)), path
    end
    expect(page.at_css("turbo-cable-stream-source#host_stream_#{media.id}")["data-turbo-permanent"]).to eq("true")
  end

  it "keeps the fleet stream for the fleet list and the fleet-wide pages, and the tasks stream for the task list" do
    %w[/ /compliance /agents /onboard].each { |path| expect(streams_of(path)).to eq([ FleetBroadcast::STREAM ]), path }
    expect(streams_of("/tasks")).to eq([ TaskBroadcast::STREAM ])
  end

  it "does not refresh an open host page for another host's change or task, and does for its own" do
    media_page = streams_of("/hosts/#{media.id}")
    fleet_page = streams_of("/")
    perform_enqueued_jobs # whatever the setup changed
    web.edit!({ name: "Web B" }, actor: Audit::SYSTEM)
    create_task(web).claim!(actor: web, lease_expires_at: 5.minutes.from_now)
    ActionCable.server.pubsub.clear
    perform_enqueued_jobs
    expect(media_page.sum { |stream| ActionCable.server.pubsub.broadcasts(stream).size }).to eq(0)
    expect(fleet_page.sum { |stream| ActionCable.server.pubsub.broadcasts(stream).size }).to eq(1)

    media.edit!({ name: "Media" }, actor: Audit::SYSTEM)
    expect(refreshes_to(media_page)).to eq(1)
    create_task(media)
    expect(refreshes_to(media_page)).to eq(1)
  end

  it "does not refresh an open batch page for another batch's task" do
    batch_page = streams_of("/tasks/batches/#{create_task(media).task_batch_id}")
    perform_enqueued_jobs # the batch's own creation
    create_task(web).cancel!(actor: Audit::SYSTEM)
    expect(refreshes_to(batch_page)).to eq(0)
  end
end
