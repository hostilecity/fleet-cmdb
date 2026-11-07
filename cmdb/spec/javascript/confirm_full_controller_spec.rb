require "rails_helper"
require "open3"

# The confirm-full Stimulus controller (P2-D06, approved mockup dialogs.html#full): an advisory upload with "Full
# import" ticked opens the confirmation instead of submitting. Only a submission by the dialog's own "Import as
# full" button goes through as full, so no value left in the form can skip the dialog (review of #129); "Import
# without withdrawing" submits as partial. Run under Node with a stand-in for Stimulus and the form, loading the
# controller source as served.
RSpec.describe "confirm-full controller" do
  CONFIRM_FULL_HARNESS = <<~JS.freeze
    const source = process.argv[1].replace(/^import \\{ Controller \\}.*$/m, "class Controller {}")
    const { default: ConfirmFull } = await import("data:text/javascript," + encodeURIComponent(source))

    const setup = (checked) => {
      const log = []
      const controller = new ConfirmFull()
      controller.fullTarget = { checked }
      controller.confirmTarget = { name: "confirm_full" }
      controller.dialogTarget = { showModal: () => log.push("open"), close: () => log.push("close") }
      controller.element = { requestSubmit: () => log.push(`submit full=${controller.fullTarget.checked}`) }
      const submit = (submitter = { name: "" }) => { let prevented = false; controller.check({ submitter, preventDefault: () => { prevented = true } }); return prevented }
      return { controller, log, submit }
    }

    const partialUpload = setup(false)
    const partialPrevented = partialUpload.submit()

    const full = setup(true)
    const fullPrevented = full.submit()
    const byConfirmButton = full.submit(full.controller.confirmTarget)
    // Submitting again by the form's own button, as after going back to a cached page: the dialog opens again.
    const againPrevented = full.submit()

    const withdrawn = setup(true)
    withdrawn.submit()
    withdrawn.controller.partial()

    console.log(JSON.stringify({ partialPrevented, fullPrevented, byConfirmButton, againPrevented, full: full.log, withdrawn: withdrawn.log }))
  JS

  before { skip "node is not installed" unless system("node", "--version", out: File::NULL, err: File::NULL) }

  it "opens the confirmation for a full import every time, letting only the dialog's own button submit it as full" do
    out, err, status = Open3.capture3("node", "--input-type=module", "-e", CONFIRM_FULL_HARNESS, Rails.root.join("app/javascript/controllers/confirm_full_controller.js").read)
    raise "node failed: #{err}" unless status.success?

    expect(JSON.parse(out)).to eq("partialPrevented" => false, "fullPrevented" => true, "byConfirmButton" => false, "againPrevented" => true,
                                  "full" => [ "open", "open" ], "withdrawn" => [ "open", "close", "submit full=false" ])
  end
end
