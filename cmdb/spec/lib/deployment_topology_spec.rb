require "rails_helper"

# The optional settings for the scale steps past one VM (#198): all off by default, and a bad value stops the boot.
RSpec.describe DeploymentTopology do
  it "is off by default: no pooler, no direct database, no replica, a 100 ms replica wait, and every hostname served" do
    expect(described_class.pooler({})).to be_nil
    expect(described_class.transaction_pooler?({})).to be(false)
    expect(described_class.direct?({})).to be(false)
    expect(described_class.replica?({})).to be(false)
    expect(described_class.replica_max_wait_ms({})).to eq(100)
    expect(described_class.node_role({})).to eq("all")
    expect { described_class.validate!({}) }.not_to raise_error
  end

  it "reads each setting" do
    env = { "FLEET_DB_POOLER" => "transaction", "DIRECT_DATABASE_URL" => "postgres://db.example.lan/cmdb_production",
            "REPLICA_DATABASE_URL" => "postgres://replica.example.lan/cmdb_production", "FLEET_REPLICA_MAX_WAIT_MS" => "0",
            "FLEET_NODE_ROLE" => "agent_api" }
    expect(described_class.transaction_pooler?(env)).to be(true)
    expect(described_class.direct?(env)).to be(true)
    expect(described_class.replica?(env)).to be(true)
    expect(described_class.replica_max_wait_ms(env)).to eq(0)
    expect(described_class.node_role(env)).to eq("agent_api")
    expect(described_class.node_role("FLEET_NODE_ROLE" => "dashboard")).to eq("dashboard")
    expect(described_class.replica_max_wait_ms("FLEET_REPLICA_MAX_WAIT_MS" => "2000")).to eq(2000)
    expect { described_class.validate!(env) }.not_to raise_error
  end

  it "treats an empty pooler as none and a blank URL as unset" do
    expect(described_class.pooler("FLEET_DB_POOLER" => "")).to be_nil
    expect(described_class.direct?("DIRECT_DATABASE_URL" => " ")).to be(false)
    expect(described_class.replica?("REPLICA_DATABASE_URL" => "")).to be(false)
  end

  it "stops the boot on a bad value, naming the setting" do
    expect { described_class.pooler("FLEET_DB_POOLER" => "session") }.to raise_error(ArgumentError, 'FLEET_DB_POOLER must be unset or transaction, not "session"')
    %w[-1 2001 abc 1.5].push("").each do |value|
      expect { described_class.replica_max_wait_ms("FLEET_REPLICA_MAX_WAIT_MS" => value) }
        .to raise_error(ArgumentError, "FLEET_REPLICA_MAX_WAIT_MS must be a whole number from 0 to 2000, not #{value.inspect}")
    end
    expect { described_class.node_role("FLEET_NODE_ROLE" => "jobs") }.to raise_error(ArgumentError, 'FLEET_NODE_ROLE must be all, agent_api, or dashboard, not "jobs"')
    expect { described_class.validate!("FLEET_NODE_ROLE" => "") }.to raise_error(ArgumentError, /FLEET_NODE_ROLE/)
  end

  it "refuses a transaction pooler without a direct database, which the session-level locks need" do
    expect { described_class.validate!("FLEET_DB_POOLER" => "transaction") }
      .to raise_error(ArgumentError, "FLEET_DB_POOLER=transaction needs DIRECT_DATABASE_URL, for the session-level advisory locks")
  end
end
