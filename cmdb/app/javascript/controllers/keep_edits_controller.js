import { Controller } from "@hotwired/stimulus"

// Keeps a form the operator is editing out of live page refreshes (P1-D05, review of #53): a refresh morphs
// the page to the server's copy, which would otherwise wipe a half-typed search or an unapplied filter.
// Once the form is submitted, the new page renders it from the URL as usual.
export default class extends Controller {
  protect(event) {
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
