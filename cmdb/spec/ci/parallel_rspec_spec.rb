require "rails_helper"
require_relative "../../lib/ci/parallel_rspec"

# bin/rspec-parallel (#288). The commands are recorded, not run: a fake `run` writes what each process would have
# written, in a scratch root.
RSpec.describe ParallelRspec do
  let(:root) { Dir.mktmpdir("parallel-rspec-") }
  let(:out) { StringIO.new }
  let(:env) { {} }
  let(:commands) { [] }
  let(:outcomes) { {} } # the command's name (rspec, parallel_test, parallel_rspec) => whether it succeeds
  let(:writes) { ->(_root) { } } # what the processes leave behind, written when parallel_rspec runs
  let(:times) { [ 100.0, 142.5 ] }
  let(:runner) do
    described_class.new(paths: [], env:, root:, out:, cpus: 4, clock: -> { times.shift },
                        run: lambda { |cmd_env, *argv|
                          commands << [ cmd_env, argv ]
                          writes.call(root) if argv[2] == "parallel_rspec"
                          outcomes.fetch(argv[2], true)
                        })
  end

  # Outside GitHub Actions unless an example says otherwise, wherever the suite itself runs.
  before { allow(GithubAnnotation).to receive(:active?).and_return(false) }
  after { FileUtils.rm_rf(root) }

  def work(file) = File.join(root, described_class::WORK_DIR, file)

  def write_results(name, examples:, failures: 0, pending: 0, outside: 0, messages: [])
    File.write(work("results-#{name}.json"), JSON.generate(
      "version" => "3.13.0", "seed" => 77, "messages" => messages,
      # file => seconds, or [file that ran it, file that defines it (a shared example's support file)] => seconds
      "examples" => examples.each_with_index.map do |(file, time), i|
        ran, defined = Array(file)
        { "id" => "./#{ran}[1:#{i + 1}]", "file_path" => "./#{defined || ran}", "run_time" => time, "status" => "passed" }
      end,
      "summary" => { "example_count" => examples.size, "failure_count" => failures, "pending_count" => pending, "errors_outside_of_examples_count" => outside }
    ))
  end

  def write_annotations(name, *records) = File.write(work("annotations-#{name}.jsonl"), records.map { |r| JSON.generate(r) + "\n" }.join)

  def summary(failures: 0, outside: 0, reruns: [], examples: 3) = { summary: { examples:, failures:, pending: 0, errors_outside: outside, reruns: } }

  def annotation(text, outside: false) = { annotation: "::error title=RSpec%3A #{text}::#{text}", outside: }

  def merged = JSON.parse(File.read(File.join(root, described_class::RESULTS)))

  def annotations = out.string.lines.grep(/\A::/).map(&:chomp)

  def decode(line) = line.split("::", 3).last.gsub("%0A", "\n")

  it "names the first process's files 1, as parallel_tests numbers it \"\"" do
    expect([ nil, "", "2", 3 ].map { |n| described_class.process_name(n) }).to eq(%w[1 1 2 3])
  end

  it "runs commands with system by default, true when they succeed" do
    expect([ described_class::SYSTEM.call({}, "true"), described_class::SYSTEM.call({ "X" => "1" }, "sh", "-c", "exit $X") ]).to eq([ true, false ])
  end

  it "times the run on the monotonic clock by default" do
    expect(described_class::CLOCK.call).to be_within(1).of(Process.clock_gettime(Process::CLOCK_MONOTONIC))
  end

  describe "the number of processes" do
    it "is one per CPU by default, at most #{ParallelRspec::DEFAULT_MAX}" do
      expect(runner.processes).to eq(4)
      expect([ 1, 2, 12 ].map { |cpus| described_class.new(env:, cpus:).processes }).to eq([ 1, 2, ParallelRspec::DEFAULT_MAX ])
    end

    it "is PARALLEL_TEST_PROCESSORS when set, above the default's cap too, and at least one" do
      env["PARALLEL_TEST_PROCESSORS"] = "6"
      expect(runner.processes).to eq(6)
      env["PARALLEL_TEST_PROCESSORS"] = "0"
      expect(runner.processes).to eq(1)
    end

    it "refuses a value that is not a number" do
      env["PARALLEL_TEST_PROCESSORS"] = "four"
      expect { runner.processes }.to raise_error(ArgumentError)
    end
  end

  describe "the seed" do
    it "is SEED when set" do
      env["SEED"] = "1234"
      expect(runner.seed).to eq(1234)
    end

    it "is random otherwise, and the same for every process" do
      expect(runner.seed).to be_between(1, 0xFFFF)
      expect(runner.seed).to eq(runner.seed)
    end
  end

  context "with one process" do
    before { env["PARALLEL_TEST_PROCESSORS"] = "1" }

    it "is a plain rspec run in the test environment, with no database preparation" do
      expect(runner.run).to eq(0)
      expect(commands).to eq([ [ { "RAILS_ENV" => "test" }, %w[bundle exec rspec] ] ])
      expect(out.string).to include("Running RSpec in one process (one process)")
    end

    it "passes on the paths and SEED, and fails when rspec does" do
      env["SEED"] = "5"
      expect(described_class.new(paths: [ "spec/models" ], env:, root:, out:, run: ->(*c) { commands << c && false }).run).to eq(1)
      expect(commands.sole).to eq([ { "RAILS_ENV" => "test" }, "bundle", "exec", "rspec", "--seed", "5", "spec/models" ])
    end
  end

  it "runs in one process when DATABASE_URL or any other *_DATABASE_URL names one database for every process" do
    env["QUEUE_DATABASE_URL"] = "postgres:///cmdb_spec_queue"
    env["EMPTY_DATABASE_URL"] = ""
    expect(runner.run).to eq(0)
    expect(commands.sole.last).to eq(%w[bundle exec rspec])
    expect(out.string).to include("(QUEUE_DATABASE_URL names one database for every process)")
    env["DATABASE_URL"] = "postgres:///cmdb_spec"
    described_class.new(env:, root:, out:, run: ->(*) { true }).run
    expect(out.string).to include("(DATABASE_URL and QUEUE_DATABASE_URL name one database for every process)")
  end

  context "in parallel" do
    before { env["SEED"] = "77" }

    it "prepares every process's test databases, then runs the suite by runtime with one seed, the timed specs together" do
      expect(runner.run).to eq(0)
      # RAILS_ENV: parallel_tests sets it only in its rake tasks, and bin/ci locally runs without it (review of #293, B1).
      expect(commands).to eq([
        [ { "RAILS_ENV" => "test" }, [ "bundle", "exec", "parallel_test", "-n", "4", "--exec", "bin/rails db:prepare" ] ],
        [ { "RAILS_ENV" => "test" }, [ "bundle", "exec", "parallel_rspec", "-n", "4", "--group-by", "runtime", "--runtime-log", "spec/parallel_runtime_rspec.log",
                                       "--allowed-missing", "100", "--single", described_class::TIMED.source, "--verbose-rerun-command",
                                       "--test-options", "--seed 77", "--", "spec" ] ]
      ])
    end

    it "puts every spec with a wall-clock budget, and only those, in the timed group" do
      timed = Dir.glob("spec/**/*_spec.rb", base: Rails.root).grep(described_class::TIMED)
      expect(timed).to contain_exactly("spec/services/vulnerability_matcher_performance_spec.rb", "spec/services/cis_dry_run_performance_spec.rb",
                                       "spec/requests/api/heartbeat_performance_spec.rb", "spec/services/signals/epss_reader_spec.rb",
                                       "spec/lib/cis_rules/evaluator_spec.rb")
    end

    it "runs only the paths given" do
      described_class.new(paths: %w[spec/models spec/ci], env:, root:, out:, cpus: 2, clock: -> { 0.0 }, run: ->(_e, *argv) { commands << argv }).run
      expect(commands.last.last(3)).to eq(%w[-- spec/models spec/ci])
    end

    it "keeps each process's output in one piece in GitHub Actions" do
      allow(GithubAnnotation).to receive(:active?).and_return(true)
      runner.run
      expect(commands.last.last).to include("--serialize-stdout", "--combine-stderr")
    end

    it "removes an earlier run's coverage and results first, so they cannot fill a gap in this run's coverage" do
      stale = %w[coverage/.resultset.json coverage/.resultset.json.lock coverage/.last_run.json tmp/rspec/results.json tmp/rspec/parallel/results-9.json]
      stale.each { |file| FileUtils.mkdir_p(File.dirname(File.join(root, file))) && File.write(File.join(root, file), "{}") }
      seen = nil
      described_class.new(env:, root:, out:, cpus: 2, clock: -> { 0.0 },
                          run: ->(_e, *argv) { seen ||= stale.select { |f| File.exist?(File.join(root, f)) } if argv[2] == "parallel_test" }).run
      expect(seen).to eq([])
    end

    it "stops when a set of databases cannot be prepared" do
      outcomes["parallel_test"] = false
      expect(runner.run).to eq(1)
      expect(commands.size).to eq(1)
    end

    it "fails when any process failed" do
      outcomes["parallel_rspec"] = false
      expect(runner.run).to eq(1)
    end

    context "with each process's results" do
      let(:writes) do
        lambda do |_root|
          write_results("1", examples: { "spec/a_spec.rb" => 1.25, "spec/b_spec.rb" => 2.0 }, failures: 1, pending: 1, messages: [ "m1" ])
          write_results("2", examples: { "spec/a_spec.rb" => 0.5, "spec/c_spec.rb" => 3.0, [ "spec/c_spec.rb", "spec/support/shared.rb" ] => 0.25 },
                             outside: 2, messages: [ "m2" ])
        end
      end

      it "merges them into one set of RSpec results, naming any process that wrote none" do
        runner.run
        expect(merged).to include("version" => "3.13.0", "seed" => 77, "processes" => 4, "missing_processes" => %w[3 4], "messages" => %w[m1 m2],
                                  "summary_line" => "5 examples, 1 failure, 1 pending, 2 errors occurred outside of examples")
        expect(merged["examples"].size).to eq(5)
        expect(merged["summary"]).to eq("example_count" => 5, "failure_count" => 1, "pending_count" => 1, "errors_outside_of_examples_count" => 2, "duration" => 42.5)
      end

      it "records each file's runtime across the processes, in the checked-in log's format, shared examples in the file that ran them" do
        runner.run
        expect(File.read(File.join(root, described_class::RECORDED_RUNTIMES))).to eq("spec/a_spec.rb:1.75\nspec/b_spec.rb:2.0\nspec/c_spec.rb:3.25\n")
      end

      it "writes no annotations outside GitHub Actions" do
        runner.run
        expect(annotations).to eq([])
      end
    end

    it "still merges the others' results when a process died with its files empty or cut short (review of #293, S1)" do
      env["PARALLEL_TEST_PROCESSORS"] = "3"
      described_class.new(env:, root:, out:, clock: -> { 0.0 }, run: lambda { |_e, *argv|
        if argv[2] == "parallel_rspec"
          write_results("1", examples: { "spec/a_spec.rb" => 1.0 })
          File.write(work("results-2.json"), "")
          File.write(work("results-3.json"), '{"examples": [{"id": "./spec/b')
        end
        argv[2] != "parallel_rspec"
      }).run
      expect(merged).to include("missing_processes" => %w[2 3], "summary_line" => "1 example, 0 failures")
    end

    it "words a run of one example as RSpec does" do
      env["PARALLEL_TEST_PROCESSORS"] = "2"
      described_class.new(env:, root:, out:, clock: -> { 0.0 }, run: lambda { |_e, *argv|
        write_results("1", examples: { "spec/a_spec.rb" => 1.0 }) if argv[2] == "parallel_rspec"
        true
      }).run
      expect(merged["summary_line"]).to eq("1 example, 0 failures")
    end

    context "in GitHub Actions" do
      before do
        allow(GithubAnnotation).to receive(:active?).and_return(true)
        env["PARALLEL_TEST_PROCESSORS"] = "2"
      end

      let(:writes) do
        lambda do |_root|
          %w[1 2].each { |name| write_results(name, examples: {}) }
          write_annotations("1", annotation("load error", outside: true), *Array.new(5) { |i| annotation("a#{i}") },
                            summary(failures: 5, outside: 1, reruns: Array.new(5) { |i| "bundle exec rspec ./spec/a_spec.rb:#{i} --seed 77 # a#{i}" }))
          write_annotations("2", *Array.new(4) { |i| annotation("b#{i}") }, annotation("late load error", outside: true),
                            summary(failures: 4, outside: 1, reruns: [ "bundle exec rspec ./spec/b_spec.rb:1 --seed 77 # b" ], examples: 6))
        end
      end

      it "emits the processes' annotations within GitHub's limit for the step, then one summary for the run" do
        runner.run
        expect(annotations.size).to eq(RspecAnnotations::BUDGET + 1)
        expect(annotations.size + 1).to be <= RspecAnnotations::GITHUB_LIMIT_PER_STEP # plus bin/ci's step annotation
        expect(annotations.first(RspecAnnotations::BUDGET)).to eq([ "load error", *%w[a0 a1 a2 a3 a4 b0 b1] ].map { |t| "::error title=RSpec%3A #{t}::#{t}" })
        expect(annotations.last).to start_with("::error title=RSpec failed%3A 9 examples%2C 9 failures%2C 2 errors occurred outside of examples%2C seed 77::")
        expect(decode(annotations.last).lines.map(&:chomp)).to eq([
          "9 examples, 9 failures, 2 errors occurred outside of examples, seed 77.",
          *Array.new(5) { |i| "bundle exec rspec ./spec/a_spec.rb:#{i} --seed 77 # a#{i}" }, "bundle exec rspec ./spec/b_spec.rb:1 --seed 77 # b",
          "1 more errors outside examples are not annotated; see the job log"
        ])
      end

      it "names a process that died, even when the others passed, from its empty or cut-short files (review of #293, S1)" do
        described_class.new(env:, root:, out:, clock: -> { 0.0 }, run: lambda { |_e, *argv|
          if argv[2] == "parallel_rspec"
            write_results("1", examples: {})
            write_annotations("1", summary)
            File.write(work("results-2.json"), "")
            File.write(work("annotations-2.jsonl"), "#{JSON.generate(annotation('b0'))}\n{\"annotation\": \"::err")
          end
          argv[2] != "parallel_rspec" # the process that died fails the run
        }).run
        expect(annotations.size).to eq(2)
        expect(annotations.first).to eq("::error title=RSpec%3A b0::b0")
        expect(decode(annotations.last)).to eq("3 examples, 0 failures, seed 77.\nProcess 2 reported no results: it died or was killed; see the job log.")
        expect(merged["missing_processes"]).to eq([ "2" ])
      end

      it "prints each process's progress every heartbeat while they run (review of #293, N4)" do
        described_class.new(env:, root:, out:, clock: -> { 0.0 }, pause: ->(_seconds) { sleep 0.01 }, run: lambda { |_e, *argv|
          if argv[2] == "parallel_rspec"
            File.write(work("progress-1.txt"), "12")
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
            sleep 0.01 until out.string.include?("RSpec running") || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          end
          true
        }).run
        expect(out.string).to include("== RSpec running for 0 s; examples finished by process: 1: 12, 2: starting ==")
      end

      it "words a finished process's progress as it wrote it" do
        FileUtils.mkdir_p(work(""))
        File.write(work("progress-1.txt"), "40 done\n")
        File.write(work("progress-2.txt"), "")
        expect(runner.progress(2, 61.4)).to eq("RSpec running for 61 s; examples finished by process: 1: 40 done, 2: starting")
      end

      it "writes nothing for a passing run" do
        described_class.new(env:, root:, out:, clock: -> { 0.0 }, run: lambda { |_e, *argv|
          if argv[2] == "parallel_rspec"
            %w[1 2].each { |name| write_results(name, examples: {}) && write_annotations(name, summary, {}) }
            File.write(work("annotations-2.jsonl"), "\n", mode: "a") # a blank line is skipped
          end
          true
        }).run
        expect(annotations).to eq([])
      end
    end
  end
end
