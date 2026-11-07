import { Controller } from "@hotwired/stimulus"
import { Turbo } from "@hotwired/turbo-rails"

// Refreshes the page once, a number of seconds after it rendered (P2-D02, owner decision Q7): a rate-limited
// request button is drawn disabled with the time it can be used again, and comes back by itself when that time
// passes. The delay is counted from the server's clock when it rendered the page, so a wrong clock on the
// operator's computer cannot bring the button back early or late. A morphing refresh keeps the scroll position.
export default class extends Controller {
  static values = { seconds: Number }

  connect() {
    const delay = Math.max(this.secondsValue, 0) * 1000 + 500 // just past the time, so the server agrees
    this.timer = setTimeout(() => Turbo.visit(window.location.href, { action: "replace" }), delay)
  }

  disconnect() {
    clearTimeout(this.timer)
  }
}
