require "rails_helper"

RSpec.describe GithubAnnotationsFormatter do
  let(:output) { StringIO.new }
  let(:configuration) { instance_double(RSpec::Core::Configuration, seed: 4242, seed_used?: true) }
  let(:formatter) { described_class.new(output, configuration) }

  def lines = output.string.lines.map(&:chomp).reject(&:empty?)

  def example_double(n = 12, description: "Hosts lists every fleet column")
    instance_double(RSpec::Core::Example, location: "./spec/requests/hosts_spec.rb:#{n}", location_rerun_argument: "./spec/requests/hosts_spec.rb:#{n}",
                                          full_description: description)
  end

  def failed(example = example_double)
    instance_double(RSpec::Core::Notifications::FailedExampleNotification, example:,
                                                                           message_lines: [ "Failure/Error: expect(x).to eq(1)", "", "  expected: 1", "       got: 2" ])
  end

  def summary(failed_examples:, outside: 0)
    instance_double(RSpec::Core::Notifications::SummaryNotification, failure_count: failed_examples.size, failed_examples:,
                                                                     errors_outside_of_examples_count: outside,
                                                                     totals_line: "#{failed_examples.size} failures")
  end

  def message(text) = RSpec::Core::Notifications::MessageNotification.new(text)

  def decode(line) = line.split("::", 3).last.gsub("%0A", "\n").gsub("%0D", "\r").gsub("%25", "%")

  it "annotates a failing example at its location, with the error, the seed, and how to rerun it" do
    formatter.example_failed(failed)
    expect(lines.sole).to start_with("::error file=cmdb/spec/requests/hosts_spec.rb,line=12,title=RSpec%3A Hosts lists every fleet column::")
    expect(decode(lines.sole)).to eq("Hosts lists every fleet column\n\nFailure/Error: expect(x).to eq(1)\n\n  expected: 1\n       got: 2\n\n" \
                                     "seed 4242. Rerun: bundle exec rspec ./spec/requests/hosts_spec.rb:12 --seed 4242")
  end

  it "starts every command on a new line, even after the progress formatter's dots on the same stream" do
    output.print("..F")
    formatter.example_failed(failed)
    formatter.dump_summary(summary(failed_examples: [ example_double ]))
    expect(output.string.lines.map { |line| line[0, 8] }).to eq([ "..F\n", "::error ", "\n", "::error " ])
  end

  it "says so when the run had no random seed" do
    allow(configuration).to receive(:seed_used?).and_return(false)
    formatter.example_failed(failed)
    expect(decode(lines.sole)).to end_with("no random seed. Rerun: bundle exec rspec ./spec/requests/hosts_spec.rb:12")
  end

  it "annotates only the first few examples, leaving room for the summary within GitHub's limit of 10 per step" do
    examples = Array.new(described_class::ANNOTATION_BUDGET + 3) { |i| example_double(i + 1) }
    examples.each { |e| formatter.example_failed(failed(e)) }
    formatter.dump_summary(summary(failed_examples: examples))
    expect(lines.size).to eq(described_class::ANNOTATION_BUDGET + 1)
    expect(lines.size + 1).to be <= 10 # plus bin/ci's step annotation
    expect(lines.last).to start_with("::error title=RSpec failed%3A 11 failures%2C seed 4242::")
    expect(decode(lines.last).lines.map(&:chomp)).to eq([ "11 failures, seed 4242.", *examples.map { |e| "bundle exec rspec #{e.location_rerun_argument} --seed 4242 # #{e.full_description}" } ])
  end

  it "lists at most a fixed number of failures in the summary" do
    examples = Array.new(described_class::MAX_SUMMARY_FAILURES + 2) { |i| example_double(i + 1) }
    formatter.dump_summary(summary(failed_examples: examples))
    summary_lines = decode(lines.sole).lines.map(&:chomp)
    expect(summary_lines.size).to eq(1 + described_class::MAX_SUMMARY_FAILURES + 1)
    expect(summary_lines.last).to eq("... and 2 more")
  end

  it "annotates a spec file that fails to load, at that file" do
    formatter.message(message("\nAn error occurred while loading ./spec/requests/hosts_spec.rb.\nFailure/Error: HOSTILE\n\nNameError:\n  uninitialized constant HOSTILE"))
    expect(lines.sole).to start_with("::error file=cmdb/spec/requests/hosts_spec.rb,title=RSpec%3A error outside examples::")
    expect(decode(lines.sole)).to end_with("uninitialized constant HOSTILE\n\nseed 4242.")
  end

  it "annotates an error in a suite hook, which has no file" do
    formatter.message(message("An error occurred in a `before(:suite)` hook.\nFailure/Error: raise \"boom\""))
    expect(lines.sole).to start_with("::error title=RSpec%3A error outside examples::An error occurred in a `before(:suite)` hook.")
  end

  it "shares the budget with errors outside examples, so many load errors never push out the summary" do
    12.times { |i| formatter.message(message("An error occurred while loading ./spec/requests/x#{i}_spec.rb.\nNameError")) }
    formatter.example_failed(failed)
    formatter.dump_summary(summary(failed_examples: [ example_double ], outside: 12))
    expect(lines.size).to eq(described_class::ANNOTATION_BUDGET + 1)
    expect(lines.size + 1).to be <= 10 # plus bin/ci's step annotation
    expect(lines.first(described_class::ANNOTATION_BUDGET)).to all(include("title=RSpec%3A error outside examples"))
    expect(decode(lines.last)).to end_with("4 more errors outside examples are not annotated; see the job log")
  end

  it "ignores RSpec's other messages" do
    formatter.message(message("Run options: include {:focus=>true}"))
    formatter.message(message("No examples found."))
    expect(output.string).to eq("")
  end

  it "summarises errors outside examples even when no example failed" do
    formatter.dump_summary(summary(failed_examples: [], outside: 1))
    expect(decode(lines.sole)).to eq("0 failures, seed 4242.")
  end

  it "writes nothing for a passing run" do
    formatter.dump_summary(summary(failed_examples: []))
    expect(output.string).to eq("")
  end

  it "is registered for the notifications it handles" do
    expect(RSpec::Core::Formatters::Loader.formatters[described_class]).to contain_exactly(:example_failed, :message, :dump_summary)
  end
end
