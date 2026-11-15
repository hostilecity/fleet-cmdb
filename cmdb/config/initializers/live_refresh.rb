# Live refreshes of open dashboard pages (P1-D05, P3-DASH-TASKS, #194). Environment files may set it first.
Rails.application.configure do
  # Each stream's open pages refresh at most once in this many seconds: a burst of changes in that time is sent as
  # one refresh, at its end (LiveRefresh). A whole number from 1 to 15; anything else stops the boot.
  config.after_initialize do
    config.x.live_refresh.window ||= LiveRefresh.parse_window(ENV["FLEET_LIVE_REFRESH_SECONDS"])
  end
end
