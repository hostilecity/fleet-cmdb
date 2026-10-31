require "rails_helper"

RSpec.describe GithubAnnotation do
  it "builds an error command with file, line, and title" do
    expect(described_class.error("boom", title: "RSpec: it works", file: "cmdb/spec/x_spec.rb", line: "12"))
      .to eq("::error file=cmdb/spec/x_spec.rb,line=12,title=RSpec%3A it works::boom")
  end

  it "leaves out properties it was not given" do
    expect(described_class.error("boom", title: "bin/ci", file: nil)).to eq("::error title=bin/ci::boom")
  end

  it "escapes values so a message can never end the command or start another" do
    command = described_class.error("50%\r\n::error::injected", title: "a,b:c\n::warning::x")
    expect(command).to eq("::error title=a%2Cb%3Ac%0A%3A%3Awarning%3A%3Ax::50%25%0D%0A::error::injected")
    expect(command.lines.size).to eq(1)
  end

  it "is active only in GitHub Actions" do
    { "true" => true, nil => false, "false" => false, "1" => false }.each do |value, active|
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with("GITHUB_ACTIONS").and_return(value)
      expect(described_class.active?).to be(active)
    end
  end
end
