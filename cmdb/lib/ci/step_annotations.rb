require_relative "github_annotation"

# Prepended to ActiveSupport::ContinuousIntegration by bin/ci. In GitHub Actions, a failed step also becomes
# an error annotation naming the step and its exit status (#69). Before this, a failure in a step that writes
# no annotation of its own (setup, the audits, or RSpec failing outside any example) showed only "Process
# completed with exit code 1", and the job log cannot be read through the API.
module CiStepAnnotations
  def step(title, *command)
    super
    $stdout.puts GithubAnnotation.error(failure_message(title, $?), title: "bin/ci step failed: #{title}") if GithubAnnotation.active? && !results.last
    results
  end

  private

  def failure_message(title, status)
    outcome = if status.nil? then "did not run"
    elsif status.signaled? then "was killed by signal #{status.termsig}"
    else "exited with status #{status.exitstatus}"
    end
    "#{title} #{outcome}. Its output is in the job log and the bin-ci-log artifact; RSpec failures have their own annotations."
  end
end
