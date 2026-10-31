require_relative "../../lib/ci/github_annotation"

# Reports RSpec failures as GitHub Actions error annotations, so they show on the pull request and through the
# checks API without the job log (#69):
# - each failing example, at its file and line, with the error and the seed to reproduce it;
# - errors outside examples (a spec file that fails to load, a :suite hook), which have no example;
# - a summary with the counts, the seed, and the rerun command for every failure.
# GitHub keeps at most 10 error annotations per step, so only the first few examples get their own and the
# summary always fits.
class GithubAnnotationsFormatter
  MAX_EXAMPLE_ANNOTATIONS = 5
  MAX_SUMMARY_FAILURES = 30

  RSpec::Core::Formatters.register self, :example_failed, :message, :dump_summary

  def initialize(output, configuration = RSpec.configuration)
    @output = output
    @configuration = configuration
    @failures = 0
  end

  def example_failed(notification)
    @failures += 1
    return if @failures > MAX_EXAMPLE_ANNOTATIONS

    example = notification.example
    file, line = example.location.delete_prefix("./").split(":")
    message = [ example.full_description, notification.message_lines.join("\n"), "#{seed}. Rerun: #{rerun(example)}" ].join("\n\n")
    emit(message, title: "RSpec: #{example.full_description}", file: "cmdb/#{file}", line:)
  end

  # RSpec hands errors outside examples to formatters only as messages that start like this.
  def message(notification)
    text = notification.message.to_s.strip
    return unless text.start_with?("An error occurred")

    file = text[/\AAn error occurred while loading \.\/(\S+?)\.?$/, 1]
    emit("#{text}\n\n#{seed}.", title: "RSpec: error outside examples", file: file && "cmdb/#{file}")
  end

  def dump_summary(summary)
    return if summary.failure_count.zero? && summary.errors_outside_of_examples_count.zero?

    reruns = summary.failed_examples.first(MAX_SUMMARY_FAILURES).map { |example| "#{rerun(example)} # #{example.full_description}" }
    reruns << "... and #{summary.failure_count - MAX_SUMMARY_FAILURES} more" if summary.failure_count > MAX_SUMMARY_FAILURES
    emit([ "#{summary.totals_line}, #{seed}.", *reruns ].join("\n"), title: "RSpec failed: #{summary.totals_line}, #{seed}")
  end

  private

  def seed = @configuration.seed_used? ? "seed #{@configuration.seed}" : "no random seed"

  def rerun(example)
    "bundle exec rspec #{example.location_rerun_argument}#{" --seed #{@configuration.seed}" if @configuration.seed_used?}"
  end

  # Each command starts on a new line. The progress formatter writes its dots to the same stream without one,
  # and GitHub reads a workflow command only at the start of a line. Before #69 the annotation came out as
  # "F::error ..." and was silently ignored, so a failing example left no annotation at all.
  def emit(message, **properties) = @output.puts("\n#{GithubAnnotation.error(message, **properties)}")
end
