require "rails_helper"

RSpec.describe Backup::RestoreCheck do
  before do
    trust_release_keys
  end

  def run(expected = {}) = described_class.new(expected:).call

  context "with hosts, audit entries, and a release in place" do
    let!(:release) { import_release(signed_release(version: "1.0.0")) }

    before { create(:host) }

    it "passes, including a release download through the agent API" do
      result = run("hosts" => "1", "audit_entries" => "1", "agent_releases" => "1")

      expect(result).to be_ok
      expect(result.failures).to be_empty
      expect(result.lines).to include(/ok   the app boots/, /ok   hosts: 1 restored/, /ok   release 1.0.0: downloads through the agent API/)
    end

    it "fails when fewer rows came back than the backup recorded" do
      result = run("hosts" => "5")

      expect(result).not_to be_ok
      expect(result.failures).to contain_exactly(/hosts: 1 restored, at least 5 expected/)
    end

    it "fails when a release file is missing, or has other content than recorded" do
      File.write(release.binary_path, "x" * release.size)
      result = run

      expect(result).not_to be_ok
      expect(result.failures).to include(/release 1.0.0: binary on disk/, /release 1.0.0: downloads/)

      File.delete(release.binary_path)
      expect(run.failures).to include(/release 1.0.0: binary on disk/)
    end
  end

  it "fails on an empty database: a drill that restored nothing proves nothing" do
    result = run

    expect(result).not_to be_ok
    expect(result.failures).to contain_exactly(/hosts: 0 restored, at least 1/, /audit_entries: 0 restored, at least 1/)
    expect(result.lines).to include(/ok   no releases to download/)
  end
end
