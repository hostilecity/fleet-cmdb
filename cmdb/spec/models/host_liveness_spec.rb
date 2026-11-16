require "rails_helper"

# #192, ADR 0029: the heartbeat's own table. db/schema.rb carries its storage options by hand (the Rails schema dumper
# leaves them out), so this checks the loaded schema has them.
RSpec.describe HostLiveness do
  let(:connection) { described_class.connection }

  it "keeps half of each page free and is vacuumed early, so a heartbeat's new row version fits on its page" do
    options = connection.select_value("SELECT array_to_string(reloptions, ',') FROM pg_class WHERE oid = 'host_liveness'::regclass")
    expect(options.split(",")).to contain_exactly("fillfactor=50", "autovacuum_vacuum_scale_factor=0.01")
  end

  it "has no index but its primary key, so no heartbeat changes an indexed column" do
    expect(connection.select_values("SELECT indexname FROM pg_indexes WHERE tablename = 'host_liveness'")).to eq([ "host_liveness_pkey" ])
  end

  it "belongs to its host, which reads its state through it" do
    seen = 1.minute.ago.floor(6)
    host = create(:host, :active, last_seen_at: seen, liveness_status: "stale")
    expect(host.liveness).to have_attributes(host:, liveness_status: "stale")
    expect(host).to have_attributes(liveness_status: "stale", last_seen_at: seen)
    expect(described_class.new(host:, liveness_status: "asleep", last_seen_at: Time.current)).not_to be_valid
  end
end
