require "rails_helper"
require "open3"

# The evaluation-progress Stimulus controller (#197; review of #204): after its delay, the progress line's frame loads
# the line's next URL, so only the frame is requested; a disconnected line sets nothing. Run under Node with stand-ins
# for Stimulus, the frame, and the timer, loading the controller source as served.
RSpec.describe "evaluation-progress controller" do
  HARNESS_197 = <<~JS.freeze
    const source = process.argv[1].replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
    const timers = []
    globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms, cleared: false }); return timers.length - 1 }
    globalThis.clearTimeout = (id) => { if (timers[id]) timers[id].cleared = true }
    const { default: EvaluationProgress } = await import("data:text/javascript," + encodeURIComponent(source))

    const run = (seconds, { disconnect = false, frame = true } = {}) => {
      const turboFrame = { src: null }
      const controller = new EvaluationProgress()
      controller.urlValue = "/evaluation-runs/7/progress?tick=2"
      controller.secondsValue = seconds
      controller.element = { closest: (selector) => (frame && selector === "turbo-frame" ? turboFrame : null) }
      controller.connect()
      if (disconnect) controller.disconnect()
      const timer = timers[timers.length - 1]
      if (!timer.cleared) timer.fn()
      return { ms: timer.ms, src: turboFrame.src }
    }

    console.log(JSON.stringify([ run(6), run(-1), run(60, { disconnect: true }), run(3, { frame: false }) ]))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "loads the next line into its frame after the delay, and nothing once disconnected" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", HARNESS_197, Rails.root.join("app/javascript/controllers/evaluation_progress_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to eq([ { "ms" => 6000, "src" => "/evaluation-runs/7/progress?tick=2" }, { "ms" => 0, "src" => "/evaluation-runs/7/progress?tick=2" },
                                    { "ms" => 60_000, "src" => nil }, { "ms" => 3000, "src" => nil } ])
  end
end
