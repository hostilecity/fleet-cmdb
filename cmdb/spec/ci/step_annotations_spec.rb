require "rails_helper"
require "active_support/continuous_integration"
require_relative "../../lib/ci/step_annotations"

# bin/ci prepends CiStepAnnotations to ActiveSupport::ContinuousIntegration (#69); a subclass keeps it local here.
RSpec.describe CiStepAnnotations do
  let(:ci_class) { Class.new(ActiveSupport::ContinuousIntegration) { prepend CiStepAnnotations } }
  let(:ci) { ci_class.new }

  def annotations(&) = capture_stdout(&).lines.grep(/\A::/).map(&:chomp)

  def capture_stdout
    original = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = original
  end

  context "in GitHub Actions" do
    before { allow(GithubAnnotation).to receive(:active?).and_return(true) }

    it "names a failed step and its exit status" do
      expect(annotations { ci.step("Security: Gem audit", "sh", "-c", "exit 3") }).to eq(
        [ "::error title=bin/ci step failed%3A Security%3A Gem audit::Security: Gem audit exited with status 3. " \
          "Its output is in the job log and the bin-ci-log artifact; RSpec failures have their own annotations." ]
      )
      expect(ci.results).to eq([ false ])
      expect(ci).not_to be_success
    end

    it "says when a step was killed by a signal" do
      expect(annotations { ci.step("Tests: RSpec", "sh", "-c", "kill -KILL $$") }.sole).to include("Tests: RSpec was killed by signal 9.")
    end

    it "says when a step's command could not be run" do
      expect(annotations { ci.step("Setup", "/nonexistent/command-for-spec") }.sole).to include("Setup exited with status 127.")
    end

    it "says when there is no exit status at all" do
      expect(ci.send(:failure_message, "Setup", nil)).to start_with("Setup did not run.")
    end

    it "writes nothing for a step that passes" do
      expect(annotations { ci.step("Style: Ruby", "true") }).to eq([])
      expect(ci.results).to eq([ true ])
    end

    it "annotates each failed step of a run and keeps every result" do
      out = annotations do
        ci.report("CI") do
          step "One", "true"
          step "Two", "false"
          step "Three", "false"
        end
      end
      expect(out.map { |line| line[/title=([^:]+)::/, 1] }).to eq([ "bin/ci step failed%3A Two", "bin/ci step failed%3A Three" ])
      expect(ci.results).to eq([ true, false, false ])
    end
  end

  it "writes no annotation outside GitHub Actions, so local runs look as before" do
    allow(GithubAnnotation).to receive(:active?).and_return(false)
    expect(annotations { ci.step("Two", "false") }).to eq([])
    expect(ci.results).to eq([ false ])
  end
end
