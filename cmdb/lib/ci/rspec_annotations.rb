require_relative "github_annotation"

# The limits and the summary of RSpec's GitHub annotations (#69), shared by the formatter in a single process
# (spec/support/github_annotations_formatter.rb) and by bin/rspec-parallel, which emits one set for all its processes
# (#288).
# GitHub keeps at most 10 error annotations per step and silently drops the rest. Two are reserved, for the summary
# and for bin/ci's own "step failed" annotation; failing examples and errors outside examples share the rest, first
# come first served, and whatever does not fit is counted in the summary instead.
module RspecAnnotations
  GITHUB_LIMIT_PER_STEP = 10
  RESERVED = 2 # the summary and bin/ci's step annotation (lib/ci/step_annotations.rb)
  BUDGET = GITHUB_LIMIT_PER_STEP - RESERVED
  MAX_SUMMARY_FAILURES = 30

  module_function

  # The summary annotation: the totals and the seed, then the rerun command for each failure ("command # description").
  def summary(totals_line:, seed:, reruns:, unannotated_errors: 0, notes: [])
    lines = reruns.first(MAX_SUMMARY_FAILURES)
    lines << "... and #{reruns.size - MAX_SUMMARY_FAILURES} more" if reruns.size > MAX_SUMMARY_FAILURES
    lines << "#{unannotated_errors} more errors outside examples are not annotated; see the job log" if unannotated_errors.positive?
    GithubAnnotation.error([ "#{totals_line}, #{seed}.", *lines, *notes ].join("\n"), title: "RSpec failed: #{totals_line}, #{seed}")
  end
end
