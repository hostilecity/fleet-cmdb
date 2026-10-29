require "rails_helper"
require "open3"

# The keep-edits Stimulus controller (P1-D05, review of #53 and #63), run under Node with a minimal DOM
# stand-in. The app has no JavaScript toolchain, so this loads the controller source as it is served.
RSpec.describe "keep-edits controller" do
  KEEP_EDITS_HARNESS = <<~JS.freeze
    const source = process.argv[1].replace(/^import .*$/m, "class Controller {}") // with -e, argv[1] is the first argument
    const { default: KeepEdits } = await import("data:text/javascript," + encodeURIComponent(source))
    globalThis.HTMLSelectElement = class {}
    globalThis.document = { activeElement: null, addEventListener() {}, removeEventListener() {} }

    // A form with one text field; invalid forms have a field the server marked aria-invalid.
    const form = ({ edited = false, invalid = false }) => ({
      elements: [ { type: "text", value: edited ? "typed" : "submitted", defaultValue: "submitted" } ],
      contains: () => false,
      querySelector: (selector) => (invalid && selector.includes("aria-invalid") ? {} : null),
    })

    const blocks = (element, { submitting = false } = {}) => {
      const controller = new KeepEdits()
      controller.element = element
      controller.connect()
      if (submitting) controller.submitted()
      let prevented = false
      controller.protect({ preventDefault() { prevented = true } })
      return prevented
    }

    console.log(JSON.stringify({
      untouched: blocks(form({})),
      edited: blocks(form({ edited: true })),
      invalid: blocks(form({ invalid: true })),
      invalid_submitting: blocks(form({ invalid: true }), { submitting: true }),
    }))
  JS

  def results
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", KEEP_EDITS_HARNESS, Rails.root.join("app/javascript/controllers/keep_edits_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    JSON.parse(out)
  end

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "lets refreshes through an untouched form, and keeps an edited one" do
    expect(results).to include("untouched" => false, "edited" => true)
  end

  it "keeps a form showing errors from its own submission, even untouched, until it is submitted again" do
    expect(results).to include("invalid" => true, "invalid_submitting" => false)
  end
end
