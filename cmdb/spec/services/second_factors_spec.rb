require "rails_helper"

# The second factor (P3-S09, DEC-06, DEC-14) with the owner's numbers (Q26 to Q30): the step-up check, setting up,
# new recovery codes, and the console reset.
RSpec.describe SecondFactors do
  let(:now) { Time.zone.parse("2026-11-08 14:00:10 UTC") }
  let(:operator) { create(:operator) }
  let(:operator_session) { OperatorSession.start!(operator, now:).first }
  let!(:enrolment) { enrol_second_factor(operator, now:) }
  let(:secret) { enrolment.first }
  let(:recovery_codes) { enrolment.last }
  let(:factor) { operator.reload.second_factor }

  def step_up(code, at: now, purpose: "create_task", fresh: false, session: operator_session)
    described_class.step_up(operator_session: session, code:, purpose:, fresh:, now: at)
  end

  describe "the step-up check" do
    it "accepts a current code, opens a fixed 5-minute window for this session, and audits it" do
      result = step_up(totp_code(secret, at: now))
      expect(result).to have_attributes(status: :passed, valid_until: now + 5.minutes, recovery: nil)
      expect(operator_session.reload.second_factor_passed_at).to eq(now)
      expect(factor).to have_attributes(last_used_step: SecondFactors::Totp.step_at(now), last_accepted_at: now)
      entry = second_factor_audits.sole
      expect(entry).to have_attributes(action: "second_factor.step_up_passed", actor_type: "operator", actor_id: operator.id, target_type: "SecondFactor", target_id: factor.id)
      expect(entry.changeset).to eq("purpose" => "create_task", "method" => "authenticator app", "valid_until" => "2026-11-08T14:05:10Z")
    end

    it "passes inside the window without a code, is not extended by use, and asks again after it" do
      step_up(totp_code(secret, at: now))
      expect(step_up(nil, at: now + 4.minutes)).to have_attributes(status: :passed, valid_until: now + 5.minutes)
      expect(step_up(nil, at: now + 4.minutes + 59.seconds)).to have_attributes(status: :passed, valid_until: now + 5.minutes)
      expect(step_up(nil, at: now + 5.minutes).status).to eq(:expired)
      expect(operator_session.reload.second_factor_passed_at).to eq(now)
      expect(second_factor_audits.count).to eq(1) # a pass by the window is not an attempt
    end

    it "asks for a code when no window was ever opened, or when fresh: true" do
      expect(step_up(nil).status).to eq(:code_required)
      expect(step_up("").status).to eq(:code_required)
      step_up(totp_code(secret, at: now))
      expect(step_up(nil, at: now + 1.minute, fresh: true).status).to eq(:code_required)
      expect(step_up(totp_code(secret, at: now + 1.minute), at: now + 1.minute, fresh: true).status).to eq(:passed)
    end

    it "keeps the window to the session that passed it" do
      other = OperatorSession.start!(operator, now:).first
      step_up(totp_code(secret, at: now))
      expect(step_up(nil, session: other).status).to eq(:code_required)
    end

    it "refuses an operator with no second factor" do
      stranger = create(:operator)
      session = OperatorSession.start!(stranger, now:).first
      expect(step_up("123456", session:).status).to eq(:not_enrolled)
      expect(step_up(nil, session:).status).to eq(:not_enrolled)
      expect(second_factor_audits).to be_empty
    end

    it "accepts a code once: the same code again, or one for an earlier step, is refused as reused" do
      code = totp_code(secret, at: now)
      step_up(code)
      reused = step_up(code, at: now + 1.second, fresh: true)
      expect(reused).to have_attributes(status: :reused, attempts_left: 4)
      expect(step_up(totp_code(secret, at: now, offset: -1), at: now + 2.seconds, fresh: true).status).to eq(:reused)
      expect(step_up(totp_code(secret, at: now + 30.seconds), at: now + 30.seconds, fresh: true).status).to eq(:passed)
      expect(second_factor_audits.where(action: "second_factor.step_up_failed").map { |e| e.changeset["reason"] }).to eq(%w[reused reused])
    end

    it "allows one step of drift either side, not two" do
      expect(step_up(totp_code(secret, at: now, offset: 2)).status).to eq(:wrong)
      expect(step_up(totp_code(secret, at: now, offset: -2)).status).to eq(:wrong)
      expect(step_up(totp_code(secret, at: now, offset: 1)).status).to eq(:passed)
      expect(factor.last_used_step).to eq(SecondFactors::Totp.step_at(now) + 1)
    end

    it "locks after 5 wrong codes in 15 minutes per operator, in every session, for 15 minutes, and audits each" do
      other = OperatorSession.start!(operator, now:).first
      results = [ step_up("000000"), step_up("111111", session: other), step_up("nonsense"), step_up("ZZZZZ-ZZZZZ", session: other) ]
      expect(results.map(&:status)).to eq(%i[wrong wrong wrong wrong])
      expect(results.map(&:attempts_left)).to eq([ 4, 3, 2, 1 ])

      locked = step_up("222222", at: now + 14.minutes)
      expect(locked).to have_attributes(status: :locked, locked_until: now + 29.minutes)
      expect(step_up(totp_code(secret, at: now + 15.minutes), at: now + 15.minutes)).to have_attributes(status: :locked)
      expect(step_up(recovery_codes.first, at: now + 16.minutes, session: other).status).to eq(:locked)
      expect(step_up(nil, at: now + 20.minutes)).to have_attributes(status: :locked, locked_until: now + 29.minutes)
      expect(step_up(totp_code(secret, at: now + 29.minutes), at: now + 29.minutes).status).to eq(:passed)

      actions = second_factor_audits.pluck(:action)
      expect(actions.tally).to eq("second_factor.step_up_failed" => 7, "second_factor.locked" => 1, "second_factor.step_up_passed" => 1)
      expect(second_factor_audits.find_by(action: "second_factor.locked").changeset).to eq("purpose" => "create_task", "locked_until" => "2026-11-08T14:29:10Z")
      expect(second_factor_audits.where(action: "second_factor.step_up_failed").last(2).map { |e| e.changeset["reason"] }).to eq(%w[locked locked])
      expect(recovery_codes.map { |code| SecondFactors::RecoveryCodes.find_unused(factor, code) }).to all(be_present) # the lock spent none
    end

    it "holds a lock even inside an open window" do
      step_up(totp_code(secret, at: now))
      5.times { |i| step_up("00000#{i}", at: now + 1.minute, fresh: true) }
      expect(step_up(nil, at: now + 2.minutes).status).to eq(:locked)
    end

    it "counts wrong codes over 15 minutes from the first, then starts again; a right code clears the count" do
      4.times { step_up("000000") }
      expect(step_up("000000", at: now + 15.minutes)).to have_attributes(status: :wrong, attempts_left: 4)
      step_up(totp_code(secret, at: now + 16.minutes), at: now + 16.minutes)
      expect(factor).to have_attributes(failed_attempts: 0, failures_started_at: nil, locked_until: nil)
    end

    it "accepts each recovery code once, in any spelling, and audits what is left" do
      code = recovery_codes.first
      typed = SecondFactors::RecoveryCodes.display(code).downcase.sub("-", " - ")
      result = step_up(typed)
      expect(result).to have_attributes(status: :passed, recovery: true, codes_left: 9)
      expect(second_factor_audits.last).to have_attributes(action: "second_factor.recovery_code_used", changeset: { "purpose" => "create_task", "codes_left" => 9 })
      expect(second_factor_audits.second_to_last.changeset["method"]).to eq("recovery code")
      expect(step_up(code, fresh: true).status).to eq(:wrong)
      expect(factor.last_used_step).to be_nil # a recovery code is not a TOTP step
    end

    it "rejects an unknown purpose, so every audit entry says what the code was for" do
      expect { step_up("123456", purpose: "anything") }.to raise_error(ArgumentError, /unknown second factor purpose/)
    end

    it "keeps the key encrypted and recovery codes as HMACs in the database" do
      raw = SecondFactor.connection.select_one("SELECT secret FROM second_factors WHERE id = #{factor.id}")["secret"]
      expect(raw).not_to include(secret)
      expect(JSON.parse(raw)).to include("p", "h") # Active Record encryption's envelope
      expect(factor.secret).to eq(secret)
      digests = factor.recovery_codes.pluck(:code_digest)
      expect(digests.size).to eq(10)
      expect(digests).to all(match(/\A\h{64}\z/))
      expect(digests).not_to include(*recovery_codes)
      expect(digests).not_to include(*recovery_codes.map { |code| Digest::SHA256.hexdigest(code) })
    end
  end

  describe "setting up" do
    let(:newcomer) { create(:operator) }
    let(:newcomer_session) { OperatorSession.start!(newcomer, now:).first }
    let(:enrolment) { [ nil, nil ] } # the operator above is not needed here

    it "needs a fresh Google sign-in, shows a new key each time, and turns the factor on with the first code" do
      first = described_class.begin_enrolment!(newcomer_session, now: now + 1.minute)
      second = described_class.begin_enrolment!(newcomer_session, now: now + 2.minutes)
      expect(second).not_to eq(first)
      expect(described_class.complete_enrolment!(newcomer_session, totp_code(first, at: now + 2.minutes), now: now + 2.minutes)).to eq([ :wrong, nil ])

      status, codes = described_class.complete_enrolment!(newcomer_session, totp_code(second, at: now + 3.minutes), now: now + 3.minutes)
      expect(status).to eq(:enrolled)
      expect(codes.size).to eq(10)
      expect(codes).to all(match(SecondFactors::RecoveryCodes::FORMAT))
      expect(newcomer.reload.second_factor).to have_attributes(secret: second, enrolled_at: now + 3.minutes, last_used_step: SecondFactors::Totp.step_at(now + 3.minutes))
      expect(newcomer_session.reload).to have_attributes(pending_second_factor_secret: nil, second_factor_passed_at: now + 3.minutes)
      expect(second_factor_audits.sole).to have_attributes(action: "second_factor.enrolled", target_type: "Operator", target_id: newcomer.id,
                                                           changeset: { "method" => "authenticator app (TOTP)", "codes_issued" => 10 })
    end

    it "keeps the pending key encrypted on the session" do
      key = described_class.begin_enrolment!(newcomer_session, now:)
      raw = OperatorSession.connection.select_one("SELECT pending_second_factor_secret FROM operator_sessions WHERE id = #{newcomer_session.id}").values.first
      expect(raw).not_to include(key)
    end

    it "runs out 10 minutes after the Google sign-in" do
      expect(described_class.begin_enrolment!(newcomer_session, now: now + 10.minutes)).to be_nil
      key = described_class.begin_enrolment!(newcomer_session, now: now + 9.minutes)
      expect(described_class.complete_enrolment!(newcomer_session, totp_code(key, at: now + 10.minutes), now: now + 10.minutes)).to eq([ :expired, nil ])
      expect(newcomer.reload.second_factor).to be_nil
    end

    it "has nothing to check without a key shown in this session" do
      expect(described_class.complete_enrolment!(newcomer_session, "123456", now:)).to eq([ :expired, nil ])
    end
  end

  describe "moving to a new phone" do
    def approve_with_code(at:)
      result = step_up(totp_code(secret, at:), at:, purpose: "replace_second_factor", fresh: true)
      described_class.approve_replacement!(operator_session, now: at) if result.passed?
      result
    end

    it "needs its own approved code as well as the fresh sign-in, then replaces the key and codes and ends other sessions' state" do
      other = OperatorSession.start!(operator, now:).first
      described_class.step_up(operator_session: other, code: totp_code(secret, at: now), purpose: "create_task", now:)

      approve_with_code(at: now + 30.seconds)
      key = described_class.begin_enrolment!(operator_session, now: now + 1.minute)
      status, codes = described_class.complete_enrolment!(operator_session, totp_code(key, at: now + 2.minutes), now: now + 2.minutes)

      expect(status).to eq(:replaced)
      expect(factor.secret).to eq(key)
      expect(SecondFactors::RecoveryCodes.find_unused(factor, recovery_codes.first)).to be_nil
      expect(SecondFactors::RecoveryCodes.find_unused(factor, codes.first)).to be_present
      expect(other.reload.second_factor_passed_at).to be_nil
      expect(operator_session.reload).to have_attributes(second_factor_replacement_approved_at: nil, pending_second_factor_secret: nil, second_factor_passed_at: now + 2.minutes)
      expect(second_factor_audits.last).to have_attributes(action: "second_factor.replaced", target_id: operator.id)
      expect(step_up(totp_code(secret, at: now + 3.minutes), at: now + 3.minutes, fresh: true).status).to eq(:wrong) # the old app stops working
    end

    it "is not started by an ordinary open window, or by an approval older than 5 minutes (review of #165)" do
      step_up(totp_code(secret, at: now))
      expect(described_class.window_open?(operator_session, now: now + 1.minute)).to be(true)
      expect(described_class.begin_enrolment!(operator_session, now: now + 1.minute)).to be_nil

      approve_with_code(at: now + 30.seconds)
      expect(described_class.begin_enrolment!(operator_session, now: now + 5.minutes + 30.seconds)).to be_nil
    end

    it "cannot be completed without an approval, so a pending key from before the factor existed does not replace it" do
      described_class.reset!(operator.email)
      key = described_class.begin_enrolment!(operator_session, now:)
      enrol_second_factor(operator, now:) # another session set one up meanwhile
      expect(described_class.complete_enrolment!(operator_session, totp_code(key, at: now), now:)).to eq([ :expired, nil ])
    end

    it "is refused while the step-up is locked, even after it started, and changes nothing (review of #165)" do
      approve_with_code(at: now)
      key = described_class.begin_enrolment!(operator_session, now: now + 1.minute)
      5.times { |i| step_up("00000#{i}", at: now + 1.minute, fresh: true) } # from another browser, say
      expect(described_class.begin_enrolment!(operator_session, now: now + 2.minutes)).to be_nil
      expect(described_class.complete_enrolment!(operator_session, totp_code(key, at: now + 2.minutes), now: now + 2.minutes)).to eq([ :locked, nil ])
      expect(factor).to have_attributes(secret:, failed_attempts: 5)
      expect(SecondFactors::RecoveryCodes.find_unused(factor, recovery_codes.first)).to be_present
    end

    it "makes a window that was cleared by a replacement unusable, even for a request that read it before (review of #165)" do
      other = OperatorSession.start!(operator, now:).first
      described_class.step_up(operator_session: other, code: totp_code(secret, at: now), purpose: "create_task", now:)
      stale = OperatorSession.find(other.id) # loaded while the window was open
      expect(stale.second_factor_passed_at).to be_present

      approve_with_code(at: now + 30.seconds)
      key = described_class.begin_enrolment!(operator_session, now: now + 1.minute)
      described_class.complete_enrolment!(operator_session, totp_code(key, at: now + 1.minute), now: now + 1.minute)

      expect(described_class.step_up(operator_session: stale, code: nil, purpose: "create_task", now: now + 2.minutes).status).to eq(:code_required)
    end
  end

  it "makes new recovery codes in place of the old ones" do
    codes = described_class.replace_recovery_codes!(operator, now:)
    expect(codes.size).to eq(10)
    expect(factor.recovery_codes.count).to eq(10)
    expect(SecondFactors::RecoveryCodes.find_unused(factor, recovery_codes.first)).to be_nil
    expect(second_factor_audits.sole).to have_attributes(action: "second_factor.recovery_codes_replaced", changeset: { "codes_issued" => 10 })
  end

  describe ".reset! (the console reset)" do
    it "removes the factor and its codes, ends every window and pending key, and audits it as the system" do
      step_up(totp_code(secret, at: now))
      described_class.reset!(" #{operator.email.upcase} ")
      expect(SecondFactor.count).to eq(0)
      expect(SecondFactorRecoveryCode.count).to eq(0)
      expect(operator_session.reload.second_factor_passed_at).to be_nil
      expect(second_factor_audits.last).to have_attributes(action: "second_factor.reset", actor_type: "system", target_type: "Operator", target_id: operator.id,
                                                           changeset: { "second_factor" => [ "authenticator app (TOTP)", nil ], "source" => "bin/rails second_factor:reset on the server" })
      expect(step_up("123456").status).to eq(:not_enrolled)
    end

    it "says when there is nothing to reset" do
      expect { described_class.reset!("nobody@example.com") }.to raise_error(SecondFactors::NotEnrolled, /no operator has signed in/)
      described_class.reset!(operator.email)
      expect { described_class.reset!(operator.email) }.to raise_error(SecondFactors::NotEnrolled, /has no second factor/)
    end
  end
end
