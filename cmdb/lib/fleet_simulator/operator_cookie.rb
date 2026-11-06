module FleetSimulator
  # A signed-in dashboard session for timing the fleet list, without Google. Development and test only: it
  # allowlists simulator@example.com (audited), creates its operator record directly, which the dashboard never
  # does (FR-S.4), and writes the session token into the encrypted session cookie the way sign-in does.
  module OperatorCookie
    EMAIL = "simulator@example.com"

    module_function

    def operator
      raise "the fleet simulator never signs in to a production dashboard" if Rails.env.production?

      OperatorAllowlistEntry.allow!(EMAIL, actor: Audit::SYSTEM) unless OperatorAllowlistEntry.allowed?(EMAIL)
      Operator.create_or_find_by!(google_uid: "fleet-simulator") { |op| op.assign_attributes(email: EMAIL, name: "Fleet simulator") }
    end

    # "name=value" for a Cookie header.
    def header(host)
      _session, token = OperatorSession.start!(operator)
      key = Rails.application.config.session_options.fetch(:key)
      env = Rails.application.env_config.merge("HTTP_HOST" => host, "rack.input" => StringIO.new)
      jar = ActionDispatch::Request.new(env).cookie_jar
      jar.encrypted[key] = { value: { "session_id" => SecureRandom.hex(16), "operator_session_token" => token } }
      "#{key}=#{CGI.escape(jar[key])}"
    end
  end
end
