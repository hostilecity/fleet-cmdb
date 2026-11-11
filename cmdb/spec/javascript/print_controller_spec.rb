require "rails_helper"
require "open3"

# The print Stimulus controller (P3-S09, the recovery codes page): a button that prints, since the CSP forbids inline handlers.
RSpec.describe "print controller" do
  HARNESS_PRINT = <<~JS.freeze
    const source = process.argv[1].replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
    let printed = 0
    globalThis.window = { print: () => { printed += 1 } }
    const { default: Print } = await import("data:text/javascript," + encodeURIComponent(source))
    new Print().print()
    console.log(JSON.stringify({ printed }))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "prints the page" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", HARNESS_PRINT, Rails.root.join("app/javascript/controllers/print_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to eq("printed" => 1)
  end
end
