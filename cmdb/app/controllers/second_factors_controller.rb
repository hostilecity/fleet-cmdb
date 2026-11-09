# Your second factor, under Settings (P3-S09, mockups second-factor.html, totp-enrol.html, totp-recovery-codes.html).
# Each operator sees and sets up only their own. Setting up is three steps: a fresh Google sign-in, scanning a key
# shown once, and checking one code; the factor is on before the 10 recovery codes are shown (Q28). Moving to a new
# phone first asks for a code from the current authenticator or a recovery code. Nothing here removes a factor.
#
# Every page here is served with no-store, and the pages that show a key or codes are kept out of Turbo's cache.
class SecondFactorsController < ApplicationController
  before_action { response.headers["Cache-Control"] = "no-store" }
  before_action :load_factor

  def show
    return unless @factor

    @codes = @factor.recovery_codes.to_a
    @last_recovery_use = @codes.filter_map(&:used_at).max
  end

  # Step by step: the current code (moving to a new phone), the Google sign-in, then the key. Showing the key
  # again makes a new one, so a key is shown only once.
  def setup
    now = Time.current
    @step = if @factor && (@factor.locked?(now) || !SecondFactors.replacement_approved?(Current.operator_session, now:)) then :replace
    elsif !SecondFactors.fresh_sign_in?(Current.operator_session, now:) then :reauth
    else :scan
    end
    @secret = SecondFactors.begin_enrolment!(Current.operator_session, now:) if @step == :scan
  end

  # Moving to a new phone: a code from the current authenticator or a recovery code, always asked for.
  def verify
    return redirect_to(setup_second_factor_path) unless @factor

    result = require_second_factor!(purpose: "replace_second_factor", fresh: true)
    return unless result.passed?

    SecondFactors.approve_replacement!(Current.operator_session)
    flash[:notice] = "Recovery code used. You have #{result.codes_left} left." if result.recovery
    redirect_to setup_second_factor_path
  end

  def enrol
    status, @codes = SecondFactors.complete_enrolment!(Current.operator_session, params[SecondFactorRequired::PARAM])
    case status
    when :wrong
      @step = :scan
      @secret = Current.operator_session.pending_second_factor_secret
      @wrong_code = true
      render :setup, status: :unprocessable_content
    when :expired
      redirect_to setup_second_factor_path, alert: "That setup page ran out (10 minutes after the Google sign-in). Nothing was set up. Start again."
    when :locked
      @step = :replace
      render :setup, status: :too_many_requests
    else
      @replaced = status == :replaced
      render :recovery_codes
    end
  end

  def new_recovery_codes
    redirect_to second_factor_path unless @factor
  end

  def create_recovery_codes
    return redirect_to(second_factor_path) unless @factor

    result = require_second_factor!(purpose: "replace_recovery_codes", fresh: true)
    return unless result.passed?

    @codes = SecondFactors.replace_recovery_codes!(current_operator)
    @new_codes = true
    render :recovery_codes
  end

  private

  def load_factor
    @factor = SecondFactor.find_by(operator: current_operator)
  end

  # A refused code shows the same page again with the box in its new state, and nothing done.
  def second_factor_refused(result)
    @step = :replace
    status = result.status == :locked ? :too_many_requests : :unprocessable_content
    action_name == "verify" ? render(:setup, status:) : render(:new_recovery_codes, status:)
  end
end
