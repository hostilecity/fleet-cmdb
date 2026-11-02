require "rails_helper"

RSpec.describe Releases::StoreCheck do
  before { trust_release_keys }

  it "is healthy with no releases" do
    expect(described_class.problems).to eq([])
    expect(described_class).to be_healthy
  end

  it "is healthy when the newest release's binary is present with the recorded size" do
    import_release(signed_release(version: "1.0.0"))
    import_release(signed_release(version: "1.1.0"))

    expect(described_class).to be_healthy
  end

  it "names the newest release when its binary is missing or the wrong size" do
    older = import_release(signed_release(version: "1.0.0"))
    newest = import_release(signed_release(version: "1.1.0"))

    File.write(newest.binary_path, "short")
    expect(described_class.problems).to eq([ "1.1.0" ])

    File.delete(newest.binary_path)
    expect(described_class.problems).to eq([ "1.1.0" ])

    # Only the newest release is checked: an older one's file is not what every update depends on.
    File.delete(older.binary_path)
    expect(described_class.problems).to eq([ "1.1.0" ])
  end

  it "does not look at an older release's file" do
    older = import_release(signed_release(version: "1.0.0"))
    import_release(signed_release(version: "1.1.0"))
    File.delete(older.binary_path)

    expect(described_class).to be_healthy
  end
end
