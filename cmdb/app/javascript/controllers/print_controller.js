import { Controller } from "@hotwired/stimulus"

// Prints the page (P3-S09, the recovery codes page): a button rather than an inline handler, which the CSP forbids.
export default class extends Controller {
  print() {
    window.print()
  }
}
