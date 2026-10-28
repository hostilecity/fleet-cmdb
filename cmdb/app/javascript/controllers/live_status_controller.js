import { Controller } from "@hotwired/stimulus"
import { Turbo } from "@hotwired/turbo-rails"

// Shows whether live updates are flowing (P1-D05). Watches the page's <turbo-cable-stream-source>, which
// carries a `connected` attribute while its subscription is up. While it is down the top bar reads
// "Reconnecting" and a banner warns that statuses may be out of date; when it returns the page is refreshed
// once so anything missed is caught up. If the connection stays down (for example the session ended), the
// page is checked every 30 seconds and a sign-in redirect is followed.
const GRACE_MS = 3000
const PROBE_MS = 30000
const STATES = {
  live: ["lamp online", "Live"],
  connecting: ["lamp awaiting", "Connecting"],
  lost: ["lamp stale", "Reconnecting"],
}

export default class extends Controller {
  static targets = ["indicator", "lamp", "label", "banner"]

  connect() {
    this.wasConnected = false
    this.observer = new MutationObserver(() => this.update())
    // Only the `connected` attribute: watching childList as well would see this controller's own label
    // changes and loop. The stream source is rendered with the page, so it is present when this connects.
    this.observer.observe(this.element, { subtree: true, attributes: true, attributeFilter: ["connected"] })
    this.update()
  }

  disconnect() {
    this.observer?.disconnect()
    this.clearTimers()
  }

  get source() {
    return this.element.querySelector("turbo-cable-stream-source")
  }

  update() {
    const source = this.source
    if (!this.hasIndicatorTarget) return
    if (!source) {
      this.indicatorTarget.hidden = true
      this.showBanner(false)
      return
    }
    this.indicatorTarget.hidden = false
    if (source.hasAttribute("connected")) {
      const recovering = this.lost
      this.clearTimers()
      this.lost = false
      this.wasConnected = true
      this.setState("live")
      this.showBanner(false)
      if (recovering) Turbo.visit(window.location.href, { action: "replace" })
    } else if (this.wasConnected && !this.graceTimer && !this.lost) {
      this.graceTimer = setTimeout(() => this.markLost(), GRACE_MS)
    } else if (!this.wasConnected) {
      this.setState("connecting")
    }
  }

  markLost() {
    this.graceTimer = null
    this.lost = true
    this.setState("lost")
    this.showBanner(true)
    this.probeTimer = setInterval(() => this.probe(), PROBE_MS)
  }

  async probe() {
    try {
      const response = await fetch(window.location.href, { redirect: "manual", headers: { Accept: "text/html" } })
      if (response.type === "opaqueredirect") window.location.reload()
    } catch {
      // Server unreachable: keep waiting.
    }
  }

  setState(state) {
    const [lamp, label] = STATES[state]
    if (this.lampTarget.className !== lamp) this.lampTarget.className = lamp
    if (this.labelTarget.textContent !== label) this.labelTarget.textContent = label
  }

  showBanner(show) {
    if (this.hasBannerTarget) this.bannerTarget.hidden = !show
  }

  clearTimers() {
    clearTimeout(this.graceTimer)
    clearInterval(this.probeTimer)
    this.graceTimer = null
    this.probeTimer = null
  }
}
