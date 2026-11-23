require "json"
require_relative "../../lib/ci/rspec_annotations"

# Reports RSpec failures as GitHub Actions error annotations, so they show on the pull request and through the
# checks API without the job log (#69):
# - each failing example, at its file and line, with the error and the seed to reproduce it;
# - errors outside examples (a spec file that fails to load, a :suite hook), which have no example;
# - a summary with the counts, the seed, and the rerun command for every failure.
# GitHub's limit of 10 per step is shared out as lib/ci/rspec_annotations.rb says. In one of bin/rspec-parallel's
# processes, Deferred below records the same annotations in a file instead, and the runner emits them for all its
# processes within that one limit (#288).
class GithubAnnotationsFormatter
  GITHUB_LIMIT_PER_STEP = RspecAnnotations::GITHUB_LIMIT_PER_STEP
  RESERVED = RspecAnnotations::RESERVED
  ANNOTATION_BUDGET = RspecAnnotations::BUDGET
  MAX_SUMMARY_FAILURES = RspecAnnotations::MAX_SUMMARY_FAILURES

  RSpec::Core::Formatters.register self, :example_failed, :message, :dump_summary

  def initialize(output, configuration = RSpec.configuration)
    @output = output
    @configuration = configuration
    @emitted = 0
    @unannotated_errors = 0
  end

  def example_failed(notification)
    return unless budget_left?

    example = notification.example
    file, line = example.location.delete_prefix("./").split(":")
    message = [ example.full_description, notification.message_lines.join("\n"), "#{seed}. Rerun: #{rerun(example)}" ].join("\n\n")
    emit(message, title: "RSpec: #{example.full_description}", file: "cmdb/#{file}", line:)
  end

  # RSpec hands errors outside examples to formatters only as messages that start like this.
  def message(notification)
    text = notification.message.to_s.strip
    return unless text.start_with?("An error occurred")

    return @unannotated_errors += 1 unless budget_left?

    file = text[/\AAn error occurred while loading \.\/(\S+?)\.?$/, 1]
    emit("#{text}\n\n#{seed}.", title: "RSpec: error outside examples", file: file && "cmdb/#{file}", outside: true)
  end

  def dump_summary(summary)
    return if summary.failure_count.zero? && summary.errors_outside_of_examples_count.zero?

    @output.puts("\n#{RspecAnnotations.summary(totals_line: summary.totals_line, seed:, reruns: reruns(summary), unannotated_errors: @unannotated_errors)}")
  end

  private

  def budget_left? = @emitted < ANNOTATION_BUDGET

  def seed = @configuration.seed_used? ? "seed #{@configuration.seed}" : "no random seed"

  def rerun(example)
    "bundle exec rspec #{example.location_rerun_argument}#{" --seed #{@configuration.seed}" if @configuration.seed_used?}"
  end

  def reruns(summary) = summary.failed_examples.map { |example| "#{rerun(example)} # #{example.full_description}" }

  # Each command starts on a new line. The progress formatter writes its dots to the same stream without one,
  # and GitHub reads a workflow command only at the start of a line. Before #69 the annotation came out as
  # "F::error ..." and was silently ignored, so a failing example left no annotation at all.
  def emit(message, outside: false, **properties)
    @emitted += 1
    @output.puts("\n#{GithubAnnotation.error(message, **properties)}")
  end

  # In one of bin/rspec-parallel's processes: every annotation, and the summary's parts, as one JSON object per line in
  # the process's own file. No budget here: the runner applies it across all the processes (lib/ci/parallel_rspec.rb).
  class Deferred < GithubAnnotationsFormatter
    RSpec::Core::Formatters.register self, :example_failed, :message, :dump_summary

    def dump_summary(summary)
      record(summary: { examples: summary.example_count, failures: summary.failure_count, pending: summary.pending_count,
                        errors_outside: summary.errors_outside_of_examples_count, reruns: reruns(summary) })
    end

    private

    def budget_left? = true

    def emit(message, outside: false, **properties) = record(annotation: GithubAnnotation.error(message, **properties), outside:)

    def record(fields) = @output.puts(JSON.generate(fields))
  end
end
