require "rails_helper"

RSpec.describe Backup::Status do
  let(:file) { Rails.configuration.x.backup.status_file }

  it "has no last backup, and is not fresh, while the status file is missing" do
    expect(described_class.last_success_at).to be_nil
    expect(described_class).not_to be_fresh
  end

  it "is fresh within the maximum age and stale after it" do
    FileUtils.touch(file, mtime: 2.hours.ago.to_time)
    expect(described_class.last_success_at).to be_within(1.second).of(2.hours.ago)
    expect(described_class).to be_fresh

    FileUtils.touch(file, mtime: 27.hours.ago.to_time)
    expect(described_class).not_to be_fresh
    expect(described_class.fresh?(now: 26.hours.ago + 1.hour)).to be(true)
  end

  it "defaults to a daily backup with slack" do
    expect(Rails.configuration.x.backup.max_age).to eq(26.hours)
  end
end
