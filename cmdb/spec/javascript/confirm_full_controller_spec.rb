require "rails_helper"
require "open3"

# The confirm-full Stimulus controller (P2-D06, approved mockup dialogs.html#full): an advisory upload with "Full
# import" ticked opens the confirmation instead of submitting; its buttons submit as a confirmed full import or as
# a partial one. Run under Node with a stand-in for Stimulus and the form, loading the controller source as served.
RSpec.describe "confirm-full controller" do
  CONFIRM_FULL_HARNESS = <<~JS.freeze
    const source = process.argv[1].replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
    const { default: ConfirmFull } = await import("data:text/javascript," + encodeURIComponent(source))

    const setup = (checked) => {
      const log = []
      const controller = new ConfirmFull()
      controller.fullTarget = { checked }
      controller.confirmedTarget = { value: "" }
      controller.dialogTarget = { showModal: () => log.push("open"), close: () => log.push("close") }
      controller.element = { requestSubmit: () => log.push(`submit full=${controller.fullTarget.checked} confirmed=${controller.confirmedTarget.value}`) }
      const submit = () => { let prevented = false; controller.check({ preventDefault: () => { prevented = true } }); return prevented }
      return { controller, log, submit }
    }

    const partialUpload = setup(false)
    const partialPrevented = partialUpload.submit()

    const full = setup(true)
    const fullPrevented = full.submit()
    full.controller.confirm()
    const afterConfirm = full.submit()

    const withdrawn = setup(true)
    withdrawn.submit()
    withdrawn.controller.partial()

    console.log(JSON.stringify({ partialPrevented, fullPrevented, afterConfirm, full: full.log, withdrawn: withdrawn.log }))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "opens the confirmation only for a full import, and submits as confirmed or as partial" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", CONFIRM_FULL_HARNESS, Rails.root.join("app/javascript/controllers/confirm_full_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to eq("partialPrevented" => false, "fullPrevented" => true, "afterConfirm" => false,
                                  "full" => [ "open", "close", "submit full=true confirmed=1" ],
                                  "withdrawn" => [ "open", "close", "submit full=false confirmed=" ])
  end
end
