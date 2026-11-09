require "rails_helper"

# P3-S04: agent output is stored as inert, valid text within the server's limit, with truncation marked.
RSpec.describe TaskOutput do
  def clean(raw, **options) = described_class.sanitize(raw, **options)

  it "passes nil and ordinary text through" do
    expect(clean(nil)).to eq(TaskOutput::Result.new(text: nil, truncated: false))
    expect(clean("line one\n\tline two\n")).to eq(TaskOutput::Result.new(text: "line one\n\tline two\n", truncated: false))
  end

  it "keeps markup as text: escaping is the dashboard's job (P3-S10)" do
    expect(clean("<b>&amp;</b>").text).to eq("<b>&amp;</b>")
  end

  it "replaces invalid UTF-8" do
    expect(clean("ok \xFF\xFE done".b).text).to eq("ok �� done")
  end

  it "removes terminal escape sequences whole, and every control character but tab and newline" do
    raw = "\e[1;31mred\e[0m \e]0;title\a\e(Bplain\r\n\u0000\u0008\u000B\u000C\u001F\u007F\u0085\u009Bend\r"
    expect(clean(raw).text).to eq("red plain\nend")
  end

  it "removes bidirectional overrides and isolates" do
    expect(clean("a‮b⁦c⁩d‪e").text).to eq("abcde")
  end

  it "cuts the middle out of long output, marks it, and never splits a character or passes the limit" do
    raw = "#{'é' * 600}#{'-' * 500}#{'ü' * 600}"
    result = clean(raw, limit: 1_000)
    expect(result.truncated).to be(true)
    expect(result.text.bytesize).to be <= 1_000
    expect(result.text).to be_valid_encoding
    expect(result.text).to start_with("é" * 200).and end_with("ü" * 200)
    head, marker, tail = result.text.partition(/\n\[\.\.\. \d+ bytes of output cut here by the server \.\.\.\]\n/)
    expect(marker).not_to be_empty
    expect(marker[/\d+/].to_i).to eq(raw.bytesize - head.bytesize - tail.bytesize)
  end

  it "leaves output at exactly the limit alone" do
    expect(clean("x" * 64, limit: 64)).to eq(TaskOutput::Result.new(text: "x" * 64, truncated: false))
  end
end
