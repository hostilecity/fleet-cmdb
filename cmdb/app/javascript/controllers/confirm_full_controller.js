import { Controller } from "@hotwired/stimulus"

// The full import confirmation on the advisory upload form (P2-D06, approved mockup dialogs.html#full): a full
// import can mark advisories withdrawn and so resolve findings, so submitting with "Full import" ticked opens the
// dialog over the page instead. "Import as full" submits with the confirmation; "Import without withdrawing"
// clears the box and submits a partial import. The server refuses a full import without the confirmation, so
// without this controller the form comes back with an error rather than importing.
export default class extends Controller {
  static targets = ["full", "confirmed", "dialog"]

  check(event) {
    if (!this.fullTarget.checked || this.confirmedTarget.value === "1") return

    event.preventDefault()
    this.dialogTarget.showModal()
  }

  confirm() {
    this.confirmedTarget.value = "1"
    this.submit()
  }

  partial() {
    this.fullTarget.checked = false
    this.confirmedTarget.value = ""
    this.submit()
  }

  submit() {
    this.dialogTarget.close()
    this.element.requestSubmit()
  }
}
