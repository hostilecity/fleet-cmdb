import { Controller } from "@hotwired/stimulus"

// Keeps a disclosure the operator opened open through live page refreshes (the Vulnerabilities tab's package groups):
// a refresh morphs the page to the server's copy, which renders the groups collapsed and would close them. Only the
// removal of "open" is stopped, so a refresh can still open a group (a text search opens what it finds). Turbo 8's
// morph (Idiomorph) names a removal "remove" in turbo:before-morph-attribute (review of #253, B1); the spec drives
// Turbo's own morph code, so a change of that name fails it.
export default class extends Controller {
  protect(event) {
    const { attributeName, mutationType } = event.detail
    if (event.target instanceof HTMLDetailsElement && attributeName === "open" && mutationType === "remove") event.preventDefault()
  }
}
