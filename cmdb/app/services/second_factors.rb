# The operator's second factor (P3-S09, DEC-06, DEC-14): a TOTP authenticator, its recovery codes, and the step-up
# check that creating or cancelling tasks and changing task allowlists and limits require. The owner's numbers
# (docs/mockups/phase-3/index.html, Q26 to Q30) are the constants below.
#
# Everything here runs on the server. Controllers reach it through SecondFactorRequired (the step-up check) and
# SecondFactorsController (setting up); the console reset is bin/rails second_factor:reset.
module SecondFactors
  STEP_UP_WINDOW = 5.minutes # fixed, from the last accepted code, per session; using it does not extend it (Q29)
  FRESH_SIGN_IN_WINDOW = 10.minutes # a new Google round trip this recent before a key is shown (Q27)
  MAX_FAILURES = 5 # wrong codes per operator ...
  FAILURE_PERIOD = 15.minutes # ... within this time ...
  LOCK_PERIOD = 15.minutes # ... lock the step-up this long (Q30)
  METHOD = "authenticator app (TOTP)".freeze

  # Why the code was asked for, as recorded in the audit log ("For creating a task").
  PURPOSES = {
    "create_task" => "creating a task",
    "cancel_task" => "cancelling a task",
    "change_task_settings" => "changing task settings",
    "replace_second_factor" => "moving to a new phone",
    "replace_recovery_codes" => "making new recovery codes"
  }.freeze

  class NotEnrolled < StandardError; end

  # The outcome of a step-up check. status is one of:
  #   :passed         the window is open, or the code was accepted (recovery: true if it was a recovery code)
  #   :not_enrolled   the operator has no second factor
  #   :code_required  no code was given and there is no open window
  #   :expired        as :code_required, but this session had a window that ran out
  #   :wrong          the code matched nothing
  #   :reused         a 6-digit code for a step that was already accepted (a code works once)
  #   :locked         too many wrong codes; nothing is accepted until locked_until
  Result = Struct.new(:status, :purpose, :valid_until, :attempts_left, :locked_until, :recovery, :codes_left, keyword_init: true) do
    def passed? = status == :passed

    def refused_code? = status.in?(%i[wrong reused locked])
  end

  module_function

  def window_open?(operator_session, now: Time.current)
    passed_at = operator_session&.second_factor_passed_at
    passed_at.present? && passed_at > now - STEP_UP_WINDOW
  end

  def window_ends_at(operator_session) = operator_session.second_factor_passed_at&.+(STEP_UP_WINDOW)

  def fresh_sign_in?(operator_session, now: Time.current)
    signed_in_at = operator_session&.google_authenticated_at
    signed_in_at.present? && signed_in_at > now - FRESH_SIGN_IN_WINDOW
  end

  # The step-up check (see SecondFactorRequired). Without fresh:, an open window passes without a code. With
  # fresh: true a code is always needed (making new recovery codes and moving to a new phone ask for one).
  def step_up(operator_session:, code:, purpose:, fresh: false, now: Time.current)
    StepUp.new(operator_session:, code:, purpose:, fresh:, now:).call
  end

  # Where this session stands, without checking a code and without an audit entry: for drawing the code box.
  def status(operator_session, now: Time.current)
    step_up(operator_session:, code: nil, purpose: "create_task", now:)
  end

  # Starts setting up (or moving to a new phone): a new key for this session only, shown once by the caller and
  # usable until FRESH_SIGN_IN_WINDOW after the Google sign-in. Showing the page again makes a new key. Returns nil
  # if the session may not set up now: it needs a fresh Google sign-in and, to replace an existing factor, an
  # open step-up window.
  def begin_enrolment!(operator_session, now: Time.current)
    return nil unless fresh_sign_in?(operator_session, now:)
    return nil if SecondFactor.exists?(operator_id: operator_session.operator_id) && !window_open?(operator_session, now:)

    secret = Totp.generate_secret
    operator_session.update!(pending_second_factor_secret: secret)
    secret
  end

  # Checks the first code from the new authenticator against this session's pending key. On a match the factor is
  # on (or replaced) before the recovery codes are shown (Q28). Returns [status, codes]: :enrolled or :replaced with
  # the 10 new plaintext codes, or :wrong (the key stays pending) or :expired (start again) with nil.
  def complete_enrolment!(operator_session, code, now: Time.current)
    secret = operator_session.pending_second_factor_secret
    return [ :expired, nil ] unless secret.present? && fresh_sign_in?(operator_session, now:)

    step = Totp.matching_step(secret, code.to_s.gsub(/\s/, "").first(16), now:)
    return [ :wrong, nil ] unless step

    operator = operator_session.operator
    Operator.transaction do
      operator.lock! # serialises two sessions setting up at once
      factor = SecondFactor.find_or_initialize_by(operator:)
      replacing = factor.persisted?
      factor.update!(secret:, last_used_step: step, enrolled_at: now, last_accepted_at: now, failed_attempts: 0, failures_started_at: nil)
      codes = RecoveryCodes.issue!(factor, now:)
      # Windows opened with the old authenticator end, in every session; this one starts its own with the code just checked.
      operator.operator_sessions.where.not(id: operator_session.id).update_all(second_factor_passed_at: nil, pending_second_factor_secret: nil)
      operator_session.update!(pending_second_factor_secret: nil, second_factor_passed_at: now)
      Audit.record(actor: operator, action: replacing ? Audit::Actions::SECOND_FACTOR_REPLACED : Audit::Actions::SECOND_FACTOR_ENROLLED,
                   target: operator, changes: { "method" => METHOD, "codes_issued" => codes.size })
      [ replacing ? :replaced : :enrolled, codes ]
    end
  end

  # New recovery codes in place of the old ones, after a passed step-up with a fresh code. Returns the plaintext codes.
  def replace_recovery_codes!(operator, now: Time.current)
    Operator.transaction do
      factor = SecondFactor.lock.find_by!(operator:)
      codes = RecoveryCodes.issue!(factor, now:)
      Audit.record(actor: operator, action: Audit::Actions::SECOND_FACTOR_RECOVERY_CODES_REPLACED, target: operator, changes: { "codes_issued" => codes.size })
      codes
    end
  end

  # The lost-authenticator recovery (ADR 0006): from the server console only, never the web. Removes the operator's
  # authenticator and recovery codes, ends every step-up window and pending setup, and records it with the system as
  # the actor. Returns the operator.
  def reset!(email)
    operator = Operator.find_by(email: OperatorAllowlistEntry.normalize(email)) or raise NotEnrolled, "no operator has signed in as #{email}"

    Operator.transaction do
      operator.lock!
      factor = SecondFactor.find_by(operator:) or raise NotEnrolled, "#{operator.email} has no second factor"
      factor.destroy!
      operator.operator_sessions.update_all(second_factor_passed_at: nil, pending_second_factor_secret: nil)
      Audit.record(actor: Audit::SYSTEM, action: Audit::Actions::SECOND_FACTOR_RESET, target: operator,
                   changes: { "second_factor" => [ METHOD, nil ], "source" => "bin/rails second_factor:reset on the server" })
    end
    operator
  end
end
