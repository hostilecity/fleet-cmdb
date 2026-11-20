require "rails_helper"

# Reading FIRST's EPSS file (VT-S03): a gzip CSV streamed a row at a time, the model version and score date from its
# first line, malformed rows skipped and counted, and limits that refuse the whole file.
RSpec.describe Signals::EpssReader do
  def rows_of(reader) = reader.to_enum(:each).to_a

  it "reads the recorded file: model version, score date, and each row's numbers as decimal text" do
    reader = described_class.new(SignalHelpers::SIGNAL_FIXTURES.join("epss_scores-current.csv.gz"))
    rows = rows_of(reader)
    expect(reader).to have_attributes(model_version: "v2025.03.14", score_date: Date.new(2026, 11, 19), rows: 6, malformed: 0, problems: [])
    expect(rows.first).to eq([ "CVE-2026-90777", "0.94321", "0.99901" ])
    expect(rows.map(&:first)).to include("CVE-2025-80001")
  end

  it "reads the same CSV uncompressed, for an offline import, and accepts scientific notation" do
    reader = described_class.new(epss_file([ %w[CVE-2026-0001 4.3e-04 1], %w[CVE-2026-0002 0 .5], "" ], gzip: false))
    expect(rows_of(reader)).to eq([ %w[CVE-2026-0001 0.00043 1.0], %w[CVE-2026-0002 0.0 0.5] ])
    expect(reader.rows).to eq(2)
  end

  it "skips and counts rows with a malformed CVE id or a number outside 0 to 1, with their line" do
    stub_const("Signals::EpssReader::PROBLEM_LIMIT", 4)
    reader = described_class.new(epss_file([ %w[CVE-2026-0001 0.5 0.5], %w[CVE-26-1 0.5 0.5], %w[CVE-2026-0002 1.5 0.5], %w[CVE-2026-0003 0.5 -1],
                                             "CVE-2026-0004,0.5", "CVE-2026-0005,0.5,0.5,extra", %w[CVE-2026-0006 NaN 0.5] ]))
    expect(rows_of(reader).map(&:first)).to eq(%w[CVE-2026-0001])
    expect(reader.malformed).to eq(6)
    expect(reader.problems).to eq([ { "line" => 4, "problem" => "has no valid CVE id" }, { "line" => 5, "problem" => "has an EPSS score that is not a number from 0 to 1" },
                                    { "line" => 6, "problem" => "has a percentile that is not a number from 0 to 1" }, { "line" => 7, "problem" => "does not have three fields" } ])
  end

  it "refuses a file without EPSS's first line or header, a broken gzip stream, or past a limit, naming the file" do
    {
      "does not start with EPSS's model version and score date (#model_version:...,score_date:...)" => [ "cve,epss,percentile" ],
      "has a score date that is not a date" => [ "#model_version:v1,score_date:2026-13-40T00:00:00Z", "cve,epss,percentile" ],
      "has no cve,epss,percentile header on its second line" => [ "#model_version:v1,score_date:2026-11-19", "cve,score" ]
    }.each do |problem, preamble|
      expect { rows_of(described_class.new(epss_file([], preamble:), name: "epss.csv.gz")) }
        .to raise_error(Advisories::Unreadable, "epss.csv.gz #{problem}, so nothing was imported")
    end
    truncated = epss_file([ %w[CVE-2026-0001 0.5 0.5] ] * 50)
    truncated.binwrite(truncated.binread[0..-10])
    expect { rows_of(described_class.new(truncated)) }.to raise_error(Advisories::Unreadable, /is not a valid gzip file/)
    expect { rows_of(described_class.new("/nonexistent/epss.csv.gz")) }.to raise_error(Advisories::Unreadable, /epss.csv.gz is not a file/)
  end

  it "refuses a file past the compressed, uncompressed, row, or line limit" do
    path = epss_file([ %w[CVE-2026-0001 0.5 0.5], %w[CVE-2026-0002 0.5 0.5] ])
    stub_const("Signals::EpssReader::MAX_ROWS", 1)
    expect { rows_of(described_class.new(path)) }.to raise_error(Advisories::Unreadable, /has more than 1 rows/)
    stub_const("Signals::EpssReader::MAX_UNCOMPRESSED_BYTES", 80)
    expect { rows_of(described_class.new(path)) }.to raise_error(Advisories::Unreadable, /larger than 0 MiB uncompressed/)
    stub_const("Signals::EpssReader::MAX_COMPRESSED_BYTES", 10)
    expect { rows_of(described_class.new(path)) }.to raise_error(Advisories::Unreadable, /is larger than 0 MiB/)
  end

  it "refuses a line past the line limit" do
    stub_const("Signals::EpssReader::MAX_LINE_BYTES", 40)
    long = epss_file([ "CVE-2026-0001,#{'1' * 60},0.5" ], gzip: false)
    expect { rows_of(described_class.new(long)) }.to raise_error(Advisories::Unreadable, /has a line longer than 40 bytes/)
  end
end
