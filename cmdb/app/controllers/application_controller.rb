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

  # The operator for this request's session token, or nil. Sessions live server-side (OperatorSession), so
  # signing out revokes them even if a copy of the cookie is replayed.
  def operator_from_session
    token = session[:operator_session_token] or return nil

    operator_session = OperatorSession.authenticate(token)
    unless operator_session
      reset_session
      flash[:alert] = "Your session has ended. Sign in again."
      return nil
    end

    operator_session.record_activity!
    operator_session.operator
  end

  def start_session(operator)
    reset_session # a new cookie on sign-in, so a planted session cannot be reused
    _record, token = OperatorSession.start!(operator)
    session[:operator_session_token] = token
  end

  def end_session
    token = session[:operator_session_token]
    OperatorSession.find_by(token_digest: AgentApi.digest(token))&.revoke! if token.present?
    reset_session
  end
end
