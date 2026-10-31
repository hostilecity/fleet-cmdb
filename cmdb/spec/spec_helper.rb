# Coverage must start before the application code loads.
unless ENV["NO_COVERAGE"]
  require "simplecov"
  SimpleCov.start "rails" do
    enable_coverage :branch
    skip "/spec/"
  end
end

require_relative "support/github_annotations_formatter"

RSpec.configure do |config|
  # In GitHub Actions, failures also become annotations on the pull request (and readable through the API), and
  # the full results are written as JSON for the workflow to keep as an artifact (#69).
  if GithubAnnotation.active?
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
