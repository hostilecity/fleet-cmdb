require "rails_helper"

# Only signed-in operators can open a live-update connection (P1-D05, FR-S.4).
RSpec.describe ApplicationCable::Connection, type: :channel do
  let(:operator) do
    allow_operator("operator@example.com")
    Operator.create!(email: "operator@example.com", google_uid: "1000000000001", name: "Example Operator")
  end
  let(:started) { OperatorSession.start!(operator) }
  let(:operator_session) { started.first }
  let(:token) { started.last }

  def connect_with(data)
    cookies.encrypted["_fleet_cmdb_session"] = { value: data } # a Hash on its own would be read as cookie options
    connect "/cable"
  end

  it "accepts a live operator session and identifies the connection by it" do
    connect_with("operator_session_token" => token)
    expect(connection.operator_session).to eq(operator_session)
  end

  {
    "no cookie" => nil,
    "a cookie without a session token" => {},
    "an unknown token" => { "operator_session_token" => "EXAMPLE-not-a-session" }
  }.each do |name, data|
    it "rejects #{name}" do
      expect { data.nil? ? connect("/cable") : connect_with(data) }.to have_rejected_connection
    end
  end

  it "rejects a revoked session" do
    operator_session.revoke!
    expect { connect_with("operator_session_token" => token) }.to have_rejected_connection
  end

  it "rejects an operator removed from the allowlist" do
    OperatorAllowlistEntry.disallow!(operator.email, actor: Audit::SYSTEM)
    expect { connect_with("operator_session_token" => token) }.to have_rejected_connection
  end

  it "rejects a session past its idle timeout" do
    token
    travel_to(OperatorSession.idle_timeout.from_now + 1.minute) do
      expect { connect_with("operator_session_token" => token) }.to have_rejected_connection
    end
  end

  describe "while connected" do
    before do
      connect_with("operator_session_token" => token)
      allow(connection).to receive(:transmit) # the heartbeat ping; the test connection has no socket
    end

    it "closes the connection at the next check once the session is revoked" do
      allow(connection).to receive(:close)
      connection.beat
      expect(connection).not_to have_received(:close) # checked at most every RECHECK_INTERVAL

      operator_session.revoke!
      travel(ApplicationCable::Connection::RECHECK_INTERVAL + 1.second) { connection.beat }
      expect(connection).to have_received(:close).with(reason: "unauthorized", reconnect: false)
    end

    it "closes the connection once the operator leaves the allowlist" do
      allow(connection).to receive(:close)
      OperatorAllowlistEntry.disallow!(operator.email, actor: Audit::SYSTEM)
      travel(ApplicationCable::Connection::RECHECK_INTERVAL + 1.second) { connection.beat }
      expect(connection).to have_received(:close)
    end

    it "keeps a live session open" do
      allow(connection).to receive(:close)
      travel(ApplicationCable::Connection::RECHECK_INTERVAL + 1.second) { connection.beat }
      expect(connection).not_to have_received(:close)
    end
  end
end
