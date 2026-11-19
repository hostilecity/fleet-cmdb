require "rails_helper"
require "open3"

# The keep-open Stimulus controller (the Vulnerabilities tab's package groups): a live refresh (Turbo morph) does not
# close a disclosure the operator opened, but may open one. Driven by Turbo's own code (review of #253, B1): the
# morph's attribute pass (Idiomorph's morphAttributes and what it calls), Turbo's beforeAttributeUpdated callback,
# and its dispatch, cut from the turbo.js this app ships, so the event and its mutationType are Turbo's, not the spec's.
RSpec.describe "keep-open controller" do
  TURBO_JS = Pathname(Gem.loaded_specs.fetch("turbo-rails").full_gem_path).join("app/assets/javascripts/turbo.js")

  # The parts of turbo.js the harness runs, cut at their first and last lines.
  def turbo_parts
    source = TURBO_JS.read
    cut = ->(from, to) { source[source.index(from)...(source.index(to, source.index(from)) + to.length)] }
    [ cut.call("function dispatch(eventName", "\n  return event;\n}"),
      cut.call("function morphAttributes(oldNode, newNode, ctx) {", "function ignoreValueOfActiveElement(possibleActiveElement, ctx) {") + "\n return false }",
      "const beforeAttributeUpdated = " + cut.call("beforeAttributeUpdated=(attributeName, target, mutationType) => {", "\n  };").delete_prefix("beforeAttributeUpdated=") ].join("\n")
  end

  HARNESS_KEEP_OPEN = <<~JS.freeze
    const [controller, turbo] = [process.argv[1], process.argv[2]]
    class FakeElement extends EventTarget {
      constructor(attributes = {}) { super(); this.nodeType = 1; this.isConnected = true; this.map = new Map(Object.entries(attributes)) }
      get attributes() { return [...this.map].map(([name, value]) => ({ name, value })) }
      getAttribute(name) { return this.map.has(name) ? this.map.get(name) : null }
      hasAttribute(name) { return this.map.has(name) }
      setAttribute(name, value) { this.map.set(name, value) }
      removeAttribute(name) { this.map.delete(name) }
    }
    globalThis.HTMLDetailsElement = class extends FakeElement {}
    globalThis.HTMLDivElement = class extends FakeElement {}
    for (const name of ["HTMLInputElement", "HTMLOptionElement", "HTMLTextAreaElement"]) globalThis[name] = class {}
    globalThis.document = { activeElement: null, body: null, documentElement: new FakeElement() }
    const { morphAttributes, beforeAttributeUpdated } = new Function(turbo + "\\nreturn { morphAttributes, beforeAttributeUpdated }")()
    const source = controller.replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
    const { default: KeepOpen } = await import("data:text/javascript," + encodeURIComponent(source))

    // Morphs old into new as a Turbo page refresh does, with or without keep-open listening, and returns old's attributes.
    const morph = (Type, oldAttributes, newAttributes, listening) => {
      const old = new Type(oldAttributes)
      if (listening) old.addEventListener("turbo:before-morph-attribute", (event) => new KeepOpen().protect(event))
      morphAttributes(old, new Type(newAttributes), { callbacks: { beforeAttributeUpdated } })
      return Object.fromEntries(old.map)
    }
    console.log(JSON.stringify({
      opened_kept: morph(HTMLDetailsElement, { id: "g", open: "" }, { id: "g" }, true),
      opened_without_controller: morph(HTMLDetailsElement, { id: "g", open: "" }, { id: "g" }, false),
      opened_by_refresh: morph(HTMLDetailsElement, { id: "g" }, { id: "g", open: "" }, true),
      other_attribute: morph(HTMLDetailsElement, { id: "g", class: "x" }, { id: "g" }, true),
      other_element: morph(HTMLDivElement, { open: "" }, {}, true)
    }))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "stops Turbo's morph from removing open from a details element, and nothing else" do
    controller = Rails.root.join("app/javascript/controllers/keep_open_controller.js").read
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", HARNESS_KEEP_OPEN, controller, turbo_parts)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to eq(
      "opened_kept" => { "id" => "g", "open" => "" }, "opened_without_controller" => { "id" => "g" }, # Turbo itself closes it
      "opened_by_refresh" => { "id" => "g", "open" => "" }, "other_attribute" => { "id" => "g" }, "other_element" => {}
    )
  end
end
