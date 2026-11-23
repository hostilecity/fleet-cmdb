require "etc"
require "fileutils"
require "json"
require_relative "rspec_annotations"

# bin/rspec-parallel (#288): the suite in several processes with parallel_tests, each on its own set of test databases
# (TEST_ENV_NUMBER, config/database.yml), then one set of results as if it had run in one process:
# - Processes: PARALLEL_TEST_PROCESSORS, or one per CPU up to DEFAULT_MAX (GitHub's runner has 4; a laptop with 12
#   cores would otherwise make 12 sets of databases). With one, or with DATABASE_URL or any other *_DATABASE_URL set
#   (each names one database for every process), it is a plain `bundle exec rspec`.
# - Every process's databases are prepared first, in the test environment (bin/rails db:prepare: schema, queue schema,
#   and partitions).
# - Files are shared out by the runtimes in spec/parallel_runtime_rspec.log; a file not in it counts as the average, so
#   a stale log only balances the processes less well. The specs with a wall-clock budget (TIMED) all run in the first
#   process, one after another, so no two of them compete for the CPU.
# - One seed for every process, so each failure's rerun command names it.
# - Coverage: SimpleCov merges the processes' results, and the first process checks COVERAGE_MINIMUM against the merged
#   total once the others have finished. Results left by an earlier run are removed first, so they cannot fill a gap.
# - RSpec's JSON results from each process are merged into tmp/rspec/results.json, and their runtimes written to
#   tmp/rspec/parallel_runtime_rspec.log (copy it over the checked-in log to rebalance).
# - In GitHub Actions, each process records its annotations in a file, and they are emitted here within GitHub's
#   limit for the step (lib/ci/rspec_annotations.rb), with one summary for the whole run. A process that died is named
#   there and in the merged results. Each process's output is printed only when it ends, so a heartbeat prints how many
#   examples each has finished every HEARTBEAT seconds: a hung process shows before the job's timeout.
class ParallelRspec
  WORK_DIR = "tmp/rspec/parallel".freeze
  RESULTS = "tmp/rspec/results.json".freeze
  RUNTIME_LOG = "spec/parallel_runtime_rspec.log".freeze
  RECORDED_RUNTIMES = "tmp/rspec/parallel_runtime_rspec.log".freeze
  STALE_COVERAGE = %w[coverage/.resultset.json coverage/.resultset.json.lock coverage/.last_run.json].freeze
  DEFAULT_MAX = 4
  # Specs that time real work against a budget (P2-S11, P2-S14, P2-S05, the EPSS reader's, the heartbeat's p95).
  TIMED = %r{(_performance_spec|/signals/epss_reader_spec|/cis_rules/evaluator_spec)\.rb\z}
  TEST_ENV = { "RAILS_ENV" => "test" }.freeze
  HEARTBEAT = 60
  # Runs a command with its output on ours: true when it exited 0.
  SYSTEM = ->(cmd_env, *argv) { system(cmd_env, *argv) }
  CLOCK = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

  # The file names each process writes (spec/spec_helper.rb): parallel_tests numbers the first process "".
  def self.process_name(test_env_number) = test_env_number.to_s.empty? ? "1" : test_env_number.to_s

  # run: how a command runs, (env, *argv) -> true when it succeeded. clock: monotonic seconds. pause: sleeps between
  # heartbeats.
  def initialize(paths: [], env: ENV, root: Dir.pwd, out: $stdout, run: SYSTEM, clock: CLOCK, cpus: Etc.nprocessors,
                 pause: ->(seconds) { sleep(seconds) })
    @paths = paths
    @env = env
    @root = root
    @out = out
    @run = run
    @clock = clock
    @cpus = cpus
    @pause = pause
  end

  # The exit status for bin/rspec-parallel.
  def run
    count = processes
    reason = single_process_reason(count)
    return serial(reason) if reason

    clear
    say "Preparing #{count} sets of test databases"
    return 1 unless @run.call(TEST_ENV, "bundle", "exec", "parallel_test", "-n", count.to_s, "--exec", "bin/rails db:prepare")

    started = @clock.call
    passed = with_heartbeat(count, started) { @run.call(TEST_ENV, *parallel_rspec(count)) }
    merge(count, @clock.call - started)
    passed ? 0 : 1
  end

  def processes
    value = @env["PARALLEL_TEST_PROCESSORS"].to_s
    value.empty? ? @cpus.clamp(1, DEFAULT_MAX) : Integer(value, 10).clamp(1, nil)
  end

  # One line per heartbeat: how long the processes have run and how many examples each has finished.
  def progress(count, seconds)
    done = (1..count).map do |n|
      text = File.exist?(path(WORK_DIR, "progress-#{n}.txt")) ? File.read(path(WORK_DIR, "progress-#{n}.txt")).strip : ""
      "#{n}: #{text.empty? ? 'starting' : text}"
    end
    "RSpec running for #{seconds.round} s; examples finished by process: #{done.join(', ')}"
  end

  def seed = @seed ||= (@env["SEED"].to_s.empty? ? rand(1..0xFFFF) : Integer(@env["SEED"], 10))

  private

  def single_process_reason(count)
    urls = @env.to_h.keys.grep(/\A(\w+_)?DATABASE_URL\z/).reject { |key| @env[key].to_s.empty? }.sort
    if count < 2 then "one process"
    elsif urls.any? then "#{urls.join(' and ')} name#{'s' if urls.one?} one database for every process"
    end
  end

  def serial(reason)
    say "Running RSpec in one process (#{reason})"
    @run.call(TEST_ENV, "bundle", "exec", "rspec", *(@env["SEED"].to_s.empty? ? [] : [ "--seed", seed.to_s ]), *@paths) ? 0 : 1
  end

  def parallel_rspec(count)
    [ "bundle", "exec", "parallel_rspec", "-n", count.to_s, "--group-by", "runtime", "--runtime-log", RUNTIME_LOG, "--allowed-missing", "100",
      "--single", TIMED.source, "--verbose-rerun-command",
      # In the job log, each process's output in one piece: interleaved lines would break its annotations and failures.
      *(GithubAnnotation.active? ? %w[--serialize-stdout --combine-stderr] : []),
      "--test-options", "--seed #{seed}", "--", *(@paths.empty? ? [ "spec" ] : @paths) ]
  end

  # In GitHub Actions only: there each process's output waits for its end (--serialize-stdout).
  def with_heartbeat(count, started)
    return yield unless GithubAnnotation.active?

    beat = Thread.new do
      loop do
        @pause.call(HEARTBEAT)
        say progress(count, @clock.call - started)
      end
    end
    yield
  ensure
    beat&.kill
  end

  def clear
    FileUtils.rm_rf(path(WORK_DIR))
    FileUtils.mkdir_p(path(WORK_DIR))
    (STALE_COVERAGE + [ RESULTS ]).each { |file| FileUtils.rm_f(path(file)) }
  end

  def merge(count, seconds)
    names = (1..count).map(&:to_s)
    results = names.to_h { |name| [ name, read_json(path(WORK_DIR, "results-#{name}.json")) ] }
    write_results(results, seconds)
    write_runtimes(results.values.compact)
    annotate(names, results.select { |_, r| r.nil? }.keys) if GithubAnnotation.active?
  end

  def write_results(results, seconds)
    found = results.values.compact
    summary = %w[example_count failure_count pending_count errors_outside_of_examples_count].to_h { |key| [ key, found.sum { |r| r.dig("summary", key).to_i } ] }
    merged = { "version" => found.first&.fetch("version", nil), "seed" => seed, "processes" => results.size,
               "missing_processes" => results.select { |_, r| r.nil? }.keys,
               "examples" => found.flat_map { |r| r["examples"] || [] }, "messages" => found.flat_map { |r| r["messages"] || [] },
               "summary" => summary.merge("duration" => seconds),
               "summary_line" => totals_line(*summary.values_at("example_count", "failure_count", "pending_count", "errors_outside_of_examples_count")) }
    File.write(path(RESULTS), JSON.pretty_generate(merged))
  end

  def write_runtimes(results)
    times = Hash.new(0.0)
    # The file that ran the example, from its id ("./spec/a_spec.rb[1:2]"): file_path is where it is defined, which for a
    # shared example is the support file.
    results.each { |r| (r["examples"] || []).each { |e| times[e["id"].to_s.sub(/\[.*\z/, "").delete_prefix("./")] += e["run_time"].to_f } }
    File.write(path(RECORDED_RUNTIMES), times.sort.map { |file, time| "#{file}:#{time.round(2)}\n" }.join)
  end

  # without_results: processes whose results file is missing, empty, or cut short.
  def annotate(names, without_results)
    records = names.to_h { |name| [ name, read_lines(path(WORK_DIR, "annotations-#{name}.jsonl")) ] }
    annotations = records.values.flatten.select { |r| r.key?("annotation") }
    annotations.first(RspecAnnotations::BUDGET).each { |r| @out.puts("\n#{r['annotation']}") }
    summaries = records.transform_values { |rs| rs.find { |r| r.key?("summary") }&.fetch("summary") }
    missing = (summaries.select { |_, s| s.nil? }.keys | without_results).sort
    found = summaries.values.compact
    totals = %w[examples failures pending errors_outside].map { |key| found.sum { |s| s[key].to_i } }
    return if totals[1].zero? && totals[3].zero? && missing.empty?

    notes = missing.map { |name| "Process #{name} reported no results: it died or was killed; see the job log." }
    @out.puts("\n#{RspecAnnotations.summary(totals_line: totals_line(*totals), seed: "seed #{seed}", reruns: found.flat_map { |s| s['reruns'] },
                                               unannotated_errors: annotations.drop(RspecAnnotations::BUDGET).count { |r| r['outside'] }, notes:)}")
  end

  # As RSpec words it.
  def totals_line(examples, failures, pending, errors)
    line = "#{count(examples, 'example')}, #{count(failures, 'failure')}"
    line += ", #{pending} pending" if pending.positive?
    line += ", #{count(errors, 'error')} occurred outside of examples" if errors.positive?
    line
  end

  def count(number, word) = "#{number} #{word}#{'s' unless number == 1}"

  # A process that died after RSpec opened its files leaves them empty or cut short: as if it wrote none.
  def read_json(file) = File.exist?(file) ? parse(File.read(file)) : nil

  def read_lines(file) = File.exist?(file) ? File.readlines(file).filter_map { |line| parse(line) } : []

  def parse(text)
    value = JSON.parse(text) unless text.strip.empty?
    value.is_a?(Hash) ? value : nil
  rescue JSON::ParserError
    nil
  end

  def path(*parts) = File.join(@root, *parts)

  # Flushed at once: in CI stdout is a pipe (bin/ci | tee), where Ruby buffers it, and the heartbeat must show while
  # the processes run, not after them.
  def say(text)
    @out.puts("== #{text} ==")
    @out.flush
  end
end
