# Public pages on the dashboard hostname, readable without signing in.
class PagesController < ApplicationController
  allow_unauthenticated_access

  # What the dashboard keeps about the people who sign in, in plain words. Google's OAuth consent screen links
  # here, so it must load without a session.
  def privacy; end
end
