module SecondFactors
  # One step-up check (P3-S09, Q29, Q30). See SecondFactors.step_up and SecondFactorRequired.
  #
  # A code is a 6-digit TOTP code for the current 30-second step or one step either side, accepted once (a step at or
  # before the last accepted one is refused as reused), or an unused recovery code. Wrong, reused, and malformed
  # codes count towards the lock: 5 in 15 minutes per operator, not per session, so another browser gets no fresh
  # attempts; then nothing is accepted for 15 minutes. Every attempt with a code is audited, accepted or not. The
  # operator's factor row is locked for the check, so two attempts at once cannot both use one code or both escape
  # the count.
  class StepUp
    MAX_CODE_LENGTH = 32

    def initialize(operator_session:, code:, purpose:, fresh:, now:)
      raise ArgumentError, "unknown second factor purpose #{purpose.inspect}" unless PURPOSES.key?(purpose.to_s)

      @session = operator_session
      @code = code.to_s.strip
      @purpose = purpose.to_s
      @fresh = fresh
      @now = now
    end

    def call
      factor = SecondFactor.find_by(operator_id: @session.operator_id)
      return result(:not_enrolled) unless factor
      # A lock holds even inside an open window: wrong codes may mean someone else is using the session (Q30).
      return result(:locked, locked_until: factor.locked_until) if @code.empty? && factor.locked?(@now)
      return result(:passed, valid_until: SecondFactors.window_ends_at(@session)) if !@fresh && !factor.locked?(@now) && SecondFactors.window_open?(@session, now: @now)
      return result(@session.second_factor_passed_at && !SecondFactors.window_open?(@session, now: @now) ? :expired : :code_required) if @code.empty?

      SecondFactor.transaction do
        factor.lock!
        next refuse(factor, :locked) if factor.locked?(@now)

        kind, match = check(factor)
        kind == :wrong || kind == :reused ? refuse(factor, kind) : accept(factor, kind, match)
      end
    end

    private

    def operator = @session.operator

    # [:totp, step], [:recovery, record], [:reused, nil], or [:wrong, nil].
    def check(factor)
      code = @code.first(MAX_CODE_LENGTH)
      if code.match?(/\A\d{#{Totp::DIGITS}}\z/o)
        step = Totp.matching_step(factor.secret, code, now: @now) or return [ :wrong, nil ]
        factor.last_used_step && step <= factor.last_used_step ? [ :reused, nil ] : [ :totp, step ]
      elsif RecoveryCodes.normalize(code).match?(RecoveryCodes::FORMAT)
        record = RecoveryCodes.find_unused(factor, code)
        record ? [ :recovery, record ] : [ :wrong, nil ]
      else
        [ :wrong, nil ]
      end
    end

    def accept(factor, kind, match)
      factor.update!(failed_attempts: 0, failures_started_at: nil, last_accepted_at: @now, **(kind == :totp ? { last_used_step: match } : {}))
      match.update!(used_at: @now) if kind == :recovery
      @session.update!(second_factor_passed_at: @now)
      valid_until = @now + STEP_UP_WINDOW
      Audit.record(actor: operator, action: Audit::Actions::SECOND_FACTOR_STEP_UP_PASSED, target: factor,
                   changes: { "purpose" => @purpose, "method" => kind == :totp ? "authenticator app" : "recovery code", "valid_until" => valid_until.utc.iso8601 })
      return result(:passed, valid_until:) unless kind == :recovery

      codes_left = factor.recovery_codes.unused.count
      Audit.record(actor: operator, action: Audit::Actions::SECOND_FACTOR_RECOVERY_CODE_USED, target: factor, changes: { "purpose" => @purpose, "codes_left" => codes_left })
      result(:passed, valid_until:, recovery: true, codes_left:)
    end

    def refuse(factor, reason)
      if reason == :locked
        audit_failure(factor, reason, 0)
        return result(:locked, locked_until: factor.locked_until)
      end

      if factor.failures_started_at.nil? || factor.failures_started_at <= @now - FAILURE_PERIOD
        factor.assign_attributes(failed_attempts: 1, failures_started_at: @now)
      else
        factor.failed_attempts += 1
      end
      attempts_left = [ MAX_FAILURES - factor.failed_attempts, 0 ].max
      factor.locked_until = @now + LOCK_PERIOD if attempts_left.zero?
      factor.save!
      audit_failure(factor, reason, attempts_left)
      return result(reason, attempts_left:) unless attempts_left.zero?

      Audit.record(actor: operator, action: Audit::Actions::SECOND_FACTOR_LOCKED, target: factor,
                   changes: { "purpose" => @purpose, "locked_until" => factor.locked_until.utc.iso8601 })
      result(:locked, locked_until: factor.locked_until)
    end

    def audit_failure(factor, reason, attempts_left)
      Audit.record(actor: operator, action: Audit::Actions::SECOND_FACTOR_STEP_UP_FAILED, target: factor,
                   changes: { "purpose" => @purpose, "reason" => reason.to_s, "attempts_left" => attempts_left })
    end

    def result(status, **fields) = Result.new(status:, purpose: @purpose, **fields)
  end
end
