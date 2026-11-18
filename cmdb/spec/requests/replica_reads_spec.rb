require "rails_helper"

# A listed page whose replica fails while it reads (review of #237): the page is run again on the primary, answers
# 200, and the replica is skipped from then on (#198).
RSpec.describe "Replica reads in a page", :signed_in, type: :request do
  let(:replica_pool) { instance_double(ActiveRecord::ConnectionAdapters::ConnectionPool, role: :reading) }

  it "answers from the primary when the replica fails during the page, and skips the replica after" do
    roles = []
    allow(FleetCompliance).to receive(:totals).and_wrap_original do |original|
      roles << ApplicationRecord.current_role
      raise ActiveRecord::ConnectionFailed.new("replica gone", connection_pool: replica_pool) if roles.size == 1

      original.call
    end

    get "/compliance"
    expect(response).to have_http_status(:ok)
    expect(roles).to eq(%i[reading writing])
    expect(ReplicaReads.down?).to be(true)

    get "/compliance"
    expect(roles.last).to eq(:writing) # skipped: the primary, with no check of the replica
  end
end
