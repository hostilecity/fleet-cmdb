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

    # A page asked for while signed out (an approval link from the installer, P1-D07) is shown after sign-in.
    session[:return_to] = request.fullpath if request.get? && safe_return_path?(request.fullpath)
    redirect_to sign_in_path
  end

  # Only a path on this site: no scheme, no host, no protocol-relative "//", and not too long.
  def safe_return_path?(path)
    path.is_a?(String) && path.length <= 512 && path.match?(%r{\A/(?![/\\])}) && !path.start_with?("/sign_in", "/auth/")
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
    if token.present? && (operator_session = OperatorSession.find_by(token_digest: AgentApi.digest(token)))
      operator_session.revoke!
      # Close this session's live-update connections now rather than at their next check (P1-D05).
      ActionCable.server.remote_connections.where(operator_session:).disconnect(reconnect: false)
    end
    reset_session
  end
end
