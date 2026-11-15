import { Controller } from "@hotwired/stimulus"

// The progress line of a fleet-wide evaluation (#197; review of #204): after secondsValue, its frame loads urlValue,
// which renders the line again with the next, longer delay. Only the frame is requested, never the whole page, and
// the server stops the cycle when the run is done, failed, or stalled.
export default class extends Controller {
  static values = { url: String, seconds: Number }

  connect() {
    clearTimeout(this.timer)
    this.timer = setTimeout(() => {
      const frame = this.element.closest("turbo-frame")
      if (frame) frame.src = this.urlValue
    }, Math.max(this.secondsValue, 0) * 1000)
  }

  disconnect() {
    clearTimeout(this.timer)
  }
}
