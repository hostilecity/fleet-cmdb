import { Controller } from "@hotwired/stimulus"
import { Turbo } from "@hotwired/turbo-rails"

// Refreshes the page once, a number of seconds after it rendered (P2-D02, owner decision Q7): a rate-limited
// request button is drawn disabled with the time it can be used again, and comes back by itself when that time
// passes. The delay is counted from the server's clock when it rendered the page, so a wrong clock on the
// operator's computer cannot bring the button back early or late. A morphing refresh keeps the scroll position,
// and may keep this controller while giving it the next deadline (the Overview's types end at different times),
// so the timer is set again whenever the value changes (review of #118).
export default class extends Controller {
  static values = { seconds: Number }

  connect() {
    this.secondsValueChanged() // again after a reconnect, which does not call the change callback
  }

  secondsValueChanged() {
    clearTimeout(this.timer)
    const delay = Math.max(this.secondsValue, 0) * 1000 + 500 // just past the time, so the server agrees
    this.timer = setTimeout(() => Turbo.visit(window.location.href, { action: "replace" }), delay)
  }

  disconnect() {
    clearTimeout(this.timer)
  }
}
