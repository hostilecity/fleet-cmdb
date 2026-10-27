# Operator sign-in and sign-out (FR-S.4, DEC-06, P1-S01). The Google round trip is handled by OmniAuth:
# the sign-in button POSTs to /auth/google_oauth2 (CSRF-protected) and Google redirects to #create.
class SessionsController < ApplicationController
  allow_unauthenticated_access

  REFUSED = "That Google account is not allowed to sign in.".freeze

  def new
    redirect_to root_path if session[:operator_session_token] && operator_from_session
  end

  def create
    operator = OperatorSignIn.call(request.env["omniauth.auth"])
    start_session(operator)
    redirect_to root_path, notice: "Signed in as #{operator.email}."
  rescue OperatorSignIn::Refused => e
    logger.info("[sign_in] refused: #{e.message}")
    reset_session
    redirect_to sign_in_path, alert: REFUSED
  end

  def failure
    redirect_to sign_in_path, alert: "Sign-in with Google did not complete."
  end

  def destroy
    end_session
    redirect_to sign_in_path, notice: "Signed out."
  end
end
