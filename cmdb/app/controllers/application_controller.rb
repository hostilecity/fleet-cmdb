# Base for every dashboard controller. Sign-in is required by default (FR-S.4, P1-S01): a controller that
# must be public opts out with allow_unauthenticated_access. The allowlist is re-checked on every request,
# and sessions end after an idle timeout and an absolute timeout.
class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # Changes to the importmap will invalidate the etag for HTML responses
  stale_when_importmap_changes

  # Lets audit entries record which request made a change (FR-S.3).
  before_action { Current.request_id = request.request_id }
  before_action :require_operator!

  helper_method :current_operator

  def self.allow_unauthenticated_access(**options)
    skip_before_action :require_operator!, **options
  end

  private

  def current_operator = Current.operator

  def require_operator!
    Current.operator = operator_from_session
    return if Current.operator

    redirect_to sign_in_path
  end

  def operator_from_session
    operator_id = session[:operator_id] or return nil

    now = Time.current
    signed_in_at = Time.zone.at(session[:signed_in_at].to_i)
    last_seen_at = Time.zone.at(session[:last_seen_at].to_i)
    timeouts = Rails.configuration.x.sessions
    operator = Operator.find_by(id: operator_id)
    if operator.nil? || !operator.allowlisted? || now - signed_in_at > timeouts.absolute_timeout || now - last_seen_at > timeouts.idle_timeout
      reset_session
      flash[:alert] = "Your session has ended. Sign in again."
      return nil
    end

    session[:last_seen_at] = now.to_i
    operator
  end

  def start_session(operator)
    reset_session # a new session id on sign-in, so a planted session cannot be reused
    now = Time.current.to_i
    session[:operator_id] = operator.id
    session[:signed_in_at] = now
    session[:last_seen_at] = now
  end
end
