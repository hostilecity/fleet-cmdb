# Coverage must start before the application code loads.
unless ENV["NO_COVERAGE"]
  require "simplecov"
  SimpleCov.start "rails" do
    enable_coverage :branch
    skip "/spec/"
    # bin/ci runs the whole suite with COVERAGE_MINIMUM set, so a drop below 100% line coverage fails it. A run of
    # a few spec files leaves it unset and only reports.
    minimum_coverage line: Integer(ENV["COVERAGE_MINIMUM"]) if ENV["COVERAGE_MINIMUM"]
  end
end

require_relative "support/github_annotations_formatter"
require_relative "support/progress_file_formatter"

RSpec.configure do |config|
  # In GitHub Actions, failures also become annotations on the pull request (and readable through the API), and
  # the full results are written as JSON for the workflow to keep as an artifact (#69).
  # In one of bin/rspec-parallel's processes (#288), both go to the process's own files, which the runner merges
  # into the same results and annotations as one process would give (lib/ci/parallel_rspec.rb).
  if ENV["PARALLEL_TEST_GROUPS"]
    require_relative "../lib/ci/parallel_rspec"
    process = ParallelRspec.process_name(ENV["TEST_ENV_NUMBER"])
    work = File.expand_path("../#{ParallelRspec::WORK_DIR}", __dir__)
    config.add_formatter("progress")
    config.add_formatter("json", "#{work}/results-#{process}.json")
    config.add_formatter(ProgressFileFormatter, "#{work}/progress-#{process}.txt")
    config.add_formatter(GithubAnnotationsFormatter::Deferred, "#{work}/annotations-#{process}.jsonl") if GithubAnnotation.active?
  elsif GithubAnnotation.active?
    config.add_formatter("progress") # keep the usual output; adding a formatter replaces the default
    config.add_formatter(GithubAnnotationsFormatter)
    config.add_formatter("json", File.expand_path("../tmp/rspec/results.json", __dir__))
  end

  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  config.filter_run_when_matching :focus
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
end
