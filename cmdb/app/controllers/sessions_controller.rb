# Operator sign-in and sign-out (FR-S.4, DEC-06, P1-S01). The Google round trip is handled by OmniAuth:
# the sign-in button POSTs to /auth/google_oauth2 (CSRF-protected) and Google redirects to #create.
class SessionsController < ApplicationController
  allow_unauthenticated_access

  REFUSED = "That Google account is not allowed to sign in.".freeze

  def new
    redirect_to root_path if session[:operator_session_token] && operator_from_session
  end

  def create
    return reauthenticate if request.env.dig("omniauth.params", "intent") == "second_factor" && (Current.operator = operator_from_session)

    operator = OperatorSignIn.call(request.env["omniauth.auth"])
    return_to = session[:return_to] # start_session resets the session
    start_session(operator)
    redirect_to safe_return_path?(return_to) ? return_to : root_path, notice: "Signed in as #{operator.email}."
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

  private

  # The fresh Google sign-in before setting up a second factor (P3-S09, Q27). The existing session stays, and only
  # its own account counts. Without a live session the round trip is an ordinary sign-in instead.
  def reauthenticate
    OperatorSignIn.reauthenticate(request.env["omniauth.auth"], Current.operator_session)
    redirect_to setup_second_factor_path
  rescue OperatorSignIn::WrongAccount => e
    redirect_to setup_second_factor_path, alert: "That was a different Google account (#{e.email}). Sign in again as #{current_operator.email}."
  rescue OperatorSignIn::Refused => e
    logger.info("[sign_in] fresh sign-in refused: #{e.message}")
    redirect_to setup_second_factor_path, alert: "The Google sign-in did not count. Sign in again as #{current_operator.email}."
  end
end
