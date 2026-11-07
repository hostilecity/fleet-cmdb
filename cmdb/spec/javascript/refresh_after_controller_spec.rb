require "rails_helper"
require "open3"

# The refresh-after Stimulus controller (P2-D02, owner decision Q7): a rate-limited request button comes back by
# itself. Run under Node with stand-ins for Stimulus, Turbo, and the timer, loading the controller source as served.
RSpec.describe "refresh-after controller" do
  HARNESS = <<~JS.freeze
    const source = process.argv[1]
      .replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
      .replace(/^import \\{ Turbo \\}.*$/m, "const Turbo = globalThis.Turbo")
    const visits = []
    const timers = []
    globalThis.Turbo = { visit: (url, options) => visits.push([url, options.action]) }
    globalThis.window = { location: { href: "/hosts/1/config" } }
    globalThis.setTimeout = (fn, ms) => { timers.push({ fn, ms, cleared: false }); return timers.length - 1 }
    globalThis.clearTimeout = (id) => { if (timers[id]) timers[id].cleared = true }
    const { default: RefreshAfter } = await import("data:text/javascript," + encodeURIComponent(source))

    const run = (seconds, { disconnect = false } = {}) => {
      const controller = new RefreshAfter()
      controller.secondsValue = seconds
      controller.connect()
      if (disconnect) controller.disconnect()
      const timer = timers[timers.length - 1]
      if (!timer.cleared) timer.fn()
      return timer.ms
    }

    const delays = [run(180), run(-5), run(60, { disconnect: true })]

    // A morph keeps the controller and gives it the next deadline: the old timer goes, a new one is set.
    const kept = new RefreshAfter()
    kept.secondsValue = 30
    kept.connect()
    const before = timers.length
    kept.secondsValue = 240
    kept.secondsValueChanged?.()
    const rescheduled = { oldCleared: timers[before - 1].cleared, newTimer: timers.length > before ? timers[timers.length - 1].ms : null }
    console.log(JSON.stringify({ delays, visits, rescheduled }))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "refreshes the page in place just after the rate limit ends, and not at all once disconnected" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", HARNESS, Rails.root.join("app/javascript/controllers/refresh_after_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to include("delays" => [ 180_500, 500, 60_500 ], "visits" => [ [ "/hosts/1/config", "replace" ], [ "/hosts/1/config", "replace" ] ])
  end

  it "sets the timer again when a morph gives it the next deadline (review of #118)" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", HARNESS, Rails.root.join("app/javascript/controllers/refresh_after_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)["rescheduled"]).to eq("oldCleared" => true, "newTimer" => 240_500)
  end
end
