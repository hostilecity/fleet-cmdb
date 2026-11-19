require "rails_helper"
require "open3"

# The keep-open Stimulus controller (the Vulnerabilities tab's package groups): a live refresh (Turbo morph) does not
# close a disclosure the operator opened, but may open one.
RSpec.describe "keep-open controller" do
  HARNESS_KEEP_OPEN = <<~JS.freeze
    const source = process.argv[1].replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
    globalThis.HTMLDetailsElement = class {}
    const { default: KeepOpen } = await import("data:text/javascript," + encodeURIComponent(source))
    const event = (target, attributeName, mutationType) => {
      const e = { target, detail: { attributeName, mutationType }, prevented: false, preventDefault() { this.prevented = true } }
      new KeepOpen().protect(e)
      return e.prevented
    }
    const details = new HTMLDetailsElement()
    console.log(JSON.stringify([ event(details, "open", "removed"), event(details, "open", "updated"), event(details, "class", "removed"), event({}, "open", "removed") ]))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "stops only the removal of open from a details element" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", HARNESS_KEEP_OPEN, Rails.root.join("app/javascript/controllers/keep_open_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to eq([ true, false, false, false ])
  end
end
