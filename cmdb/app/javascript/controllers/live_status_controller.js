import { Controller } from "@hotwired/stimulus"
import { Turbo } from "@hotwired/turbo-rails"

// Shows whether live updates are flowing (P1-D05). Watches the page's <turbo-cable-stream-source>, which
// carries a `connected` attribute while its subscription is up. While it is down the top bar reads
// "Reconnecting" and a banner warns that statuses may be out of date; when it returns the page is refreshed
// once so anything missed is caught up. If the connection stays down (for example the session ended), the
// page is checked every 30 seconds and a sign-in redirect is followed.
const GRACE_MS = 3000
const FIRST_CONNECT_GRACE_MS = 10000
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
    this.missed = false
    this.lost = false
    this.observer = new MutationObserver(() => this.update())
    // Only the `connected` attribute: watching childList as well would see this controller's own label
    // changes and loop. The stream source is rendered with the page, so it is present when this connects.
    this.observer.observe(this.element, { subtree: true, attributes: true, attributeFilter: ["connected"] })
    // A morphing page refresh re-renders the indicator in its server state ("Connecting") while the
    // subscription stays up, so the state is reapplied after each one.
    this.onMorph = () => this.update(true)
    document.addEventListener("turbo:morph", this.onMorph)
    this.update()
  }

  disconnect() {
    this.observer?.disconnect()
    document.removeEventListener("turbo:morph", this.onMorph)
    this.clearTimers()
  }

  get source() {
    return this.element.querySelector("turbo-cable-stream-source")
  }

  update(rerendered = false) {
    const source = this.source
    if (!this.hasIndicatorTarget) return
    if (!source) {
      this.indicatorTarget.hidden = true
      this.showBanner(false)
      return
    }
    this.indicatorTarget.hidden = false
    if (source.hasAttribute("connected")) {
      // Broadcasts are not replayed, so any gap since the page was live (however short), or a first
      // connection that only arrived after its grace period, is caught up with one refresh.
      const missed = this.missed && !rerendered
      this.clearTimers()
      this.lost = false
      this.missed = false
      this.wasConnected = true
      this.setState("live")
      this.showBanner(false)
      if (missed) Turbo.visit(window.location.href, { action: "replace" })
    } else {
      if (this.wasConnected) this.missed = true
      if (!this.wasConnected && !this.lost) this.setState("connecting")
      // The grace period only delays the warning; it applies to a first connection too, so a refused or
      // failing subscription still ends in the banner and the session probe.
      if (!this.graceTimer && !this.lost) {
        this.graceTimer = setTimeout(() => this.markLost(), this.wasConnected ? GRACE_MS : FIRST_CONNECT_GRACE_MS)
      }
    }
  }

  markLost() {
    this.graceTimer = null
    this.lost = true
    this.missed = true
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
