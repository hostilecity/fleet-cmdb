# Second factor helpers (P3-S09).
module SecondFactorHelpers
  # A factor for the operator as setting up leaves it, without the pages. Returns [secret, plaintext recovery codes].
  def enrol_second_factor(operator, now: Time.current)
    secret = SecondFactors::Totp.generate_secret
    factor = SecondFactor.create!(operator:, secret:, enrolled_at: now)
    codes = SecondFactor.transaction { SecondFactors::RecoveryCodes.issue!(factor, now:) }
    [ secret, codes ]
  end

  # The code an authenticator shows at `at`, `offset` steps from then.
  def totp_code(secret, at: Time.current, offset: 0) = SecondFactors::Totp.code_at_step(secret, SecondFactors::Totp.step_at(at) + offset)

  def second_factor_audits = AuditEntry.where(action: Audit::Actions::ALL.grep(/\Asecond_factor\./)).order(:id)
end

RSpec.configure { |config| config.include SecondFactorHelpers }
