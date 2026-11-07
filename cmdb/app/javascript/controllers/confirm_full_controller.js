import { Controller } from "@hotwired/stimulus"

// The full import confirmation on the advisory upload form (P2-D06, approved mockup dialogs.html#full): a full
// import can mark advisories withdrawn and so resolve findings, so submitting with "Full import" ticked opens the
// dialog over the page instead. "Import as full" is a submit button whose own name and value (confirm_full=1) are
// the confirmation: a browser sends them only when that button submits, so no value kept in the form (one
// restored from the cache, say) can skip the dialog (review of #129). "Import without withdrawing" clears the box
// and submits a partial import. The server refuses a full import without the confirmation, so without this
// controller the form comes back with an error rather than importing.
export default class extends Controller {
  static targets = ["full", "confirm", "dialog"]

  check(event) {
    if (!this.fullTarget.checked || event.submitter === this.confirmTarget) return

    event.preventDefault()
    this.dialogTarget.showModal()
  }

  partial() {
    this.fullTarget.checked = false
    this.dialogTarget.close()
    this.element.requestSubmit()
  }
}
