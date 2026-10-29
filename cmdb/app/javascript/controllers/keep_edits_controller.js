import { Controller } from "@hotwired/stimulus"

// Keeps a form the operator is editing out of live page refreshes (P1-D05, review of #53): a refresh morphs
// the page to the server's copy, which would otherwise wipe a half-typed search or an unapplied filter.
// The response to the operator's own submission of this form (for example errors shown in place) is always
// applied: the guard is off from submit until that response has rendered.
export default class extends Controller {
  connect() {
    this.submitting = false
    this.onRendered = () => { this.submitting = false }
    document.addEventListener("turbo:morph", this.onRendered)
    document.addEventListener("turbo:load", this.onRendered)
  }

  disconnect() {
    document.removeEventListener("turbo:morph", this.onRendered)
    document.removeEventListener("turbo:load", this.onRendered)
  }

  submitted() {
    this.submitting = true
  }

  protect(event) {
    if (this.submitting) return
    if (this.edited || this.element.contains(document.activeElement)) event.preventDefault()
  }

  get edited() {
    return [...this.element.elements].some((field) => {
      if (field instanceof HTMLSelectElement) return [...field.options].some((option) => option.selected !== option.defaultSelected)
      if (field.type === "checkbox" || field.type === "radio") return field.checked !== field.defaultChecked
      return "defaultValue" in field && field.value !== field.defaultValue
    })
  }
}
