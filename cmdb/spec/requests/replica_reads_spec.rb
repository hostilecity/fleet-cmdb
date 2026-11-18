require "rails_helper"

# A listed page whose replica fails while it reads (#198; the owner's decision, 2026-11-18): the page shows a plain
# error page and is not run again. A connection-level failure marks the replica down, so the next load reads the
# primary; a cancelled query leaves the replica in use.
RSpec.describe "Replica reads in a page", :signed_in, type: :request do
  let(:replica_pool) { instance_double(ActiveRecord::ConnectionAdapters::ConnectionPool, role: :reading) }

  def fail_first_read_with(error)
    roles = []
    allow(FleetCompliance).to receive(:totals).and_wrap_original do |original|
      roles << ApplicationRecord.current_role
      raise error if roles.size == 1

      original.call
    end
    roles
  end

  it "shows an error page when the replica fails during the page, and the next load reads the primary" do
    roles = fail_first_read_with(ActiveRecord::ConnectionFailed.new("replica gone", connection_pool: replica_pool))

    get "/compliance"
    expect(response).to have_http_status(:service_unavailable)
    expect(page.at_css("h1").text).to eq("This page couldn't be loaded")
    expect(page.at_css("#replica_unavailable a")["href"]).to eq("/compliance")
    expect(roles).to eq(%i[reading]) # not run again
    expect(ReplicaReads.down?).to be(true)

    get "/compliance"
    expect(response).to have_http_status(:ok)
    expect(roles.last).to eq(:writing) # the replica is skipped: the primary
  end

  it "shows the error page on a cancelled replica query, and the next load reads the replica again" do
    roles = fail_first_read_with(ActiveRecord::QueryCanceled.new("canceling statement due to statement timeout", connection_pool: replica_pool))

    get "/compliance"
    expect(response).to have_http_status(:service_unavailable)
    expect(ReplicaReads.down?).to be_falsey

    get "/compliance"
    expect(response).to have_http_status(:ok)
    expect(roles).to eq(%i[reading reading])
  end
end
