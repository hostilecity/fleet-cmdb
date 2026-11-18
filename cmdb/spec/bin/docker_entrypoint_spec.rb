require "rails_helper"
require "open3"

# bin/docker-entrypoint (#198): migrates before the server by default, skips it with FLEET_DB_PREPARE=false, and
# refuses a transaction pooler unless migrations are off, since no node migrates through the pooler.
RSpec.describe "bin/docker-entrypoint" do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      FileUtils.cp(Rails.root.join("bin/docker-entrypoint"), File.join(dir, "entrypoint"))
      FileUtils.mkdir(File.join(dir, "bin"))
      File.write(File.join(dir, "bin/rails"), "#!/bin/sh\necho \"rails $*\"\n")
      File.chmod(0o755, File.join(dir, "bin/rails"))
      example.run
    end
  end

  def start(env, *command)
    clean = { "FLEET_DB_POOLER" => nil, "FLEET_DB_PREPARE" => nil }.merge(env)
    Open3.capture3(clean, "bash", "entrypoint", *command, chdir: @dir)
  end

  it "migrates, then starts the server, with nothing set" do
    out, _, status = start({}, "./bin/rails", "server")
    expect(status).to be_success
    expect(out.lines.map(&:chomp)).to eq([ "rails db:prepare", "rails server" ])
  end

  it "starts without migrating with FLEET_DB_PREPARE=false, and stops on another value" do
    out, _, status = start({ "FLEET_DB_PREPARE" => "false" }, "./bin/rails", "server")
    expect(status).to be_success
    expect(out).not_to include("db:prepare")
    _, err, status = start({ "FLEET_DB_PREPARE" => "yes" }, "./bin/rails", "server")
    expect(status).not_to be_success
    expect(err).to include("FLEET_DB_PREPARE must be true or false")
  end

  it "refuses a transaction pooler unless migrations are off" do
    [ {}, { "FLEET_DB_PREPARE" => "true" } ].each do |prepare|
      out, err, status = start({ "FLEET_DB_POOLER" => "transaction" }.merge(prepare), "./bin/rails", "server")
      expect(status).not_to be_success
      expect(out).to be_empty
      expect(err).to include("FLEET_DB_POOLER=transaction needs FLEET_DB_PREPARE=false")
    end
    out, _, status = start({ "FLEET_DB_POOLER" => "transaction", "FLEET_DB_PREPARE" => "false" }, "./bin/rails", "server")
    expect(status).to be_success
    expect(out).to include("rails server")
  end

  it "runs any other command as given, such as a one-off migration" do
    out, _, status = start({ "FLEET_DB_POOLER" => "transaction" }, "./bin/rails", "db:prepare")
    expect(status).to be_success
    expect(out.chomp).to eq("rails db:prepare")
  end
end
