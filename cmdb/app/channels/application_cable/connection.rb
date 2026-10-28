module ApplicationCable
  # Live updates are for signed-in operators only (P1-D05). The WebSocket handshake carries the same
  # encrypted session cookie as the dashboard, and its token must name a live OperatorSession. The session is
  # checked again every RECHECK_INTERVAL, so a connection does not outlive sign-out, a timeout, or removal
  # from the allowlist; sign-out also disconnects at once (SessionsController#destroy).
  class Connection < ActionCable::Connection::Base
    RECHECK_INTERVAL = 30.seconds

    identified_by :operator_session

    def connect
      self.operator_session = authenticated_session || reject_unauthorized_connection
      @checked_at = Time.current
    end

    # Called by the server's heartbeat every few seconds.
    def beat
      super
      recheck_session if @checked_at && Time.current - @checked_at >= RECHECK_INTERVAL
    end

    private

    def authenticated_session
      data = cookies.encrypted[Rails.application.config.session_options.fetch(:key)]
      token = data.is_a?(Hash) ? data["operator_session_token"] : nil
      OperatorSession.authenticate(token)
    end

    def recheck_session
      @checked_at = Time.current
      return if OperatorSession.still_valid?(operator_session)

      logger.info("[cable] session no longer valid; disconnecting")
      close(reason: ActionCable::INTERNAL[:disconnect_reasons][:unauthorized], reconnect: false)
    end
  end
end
