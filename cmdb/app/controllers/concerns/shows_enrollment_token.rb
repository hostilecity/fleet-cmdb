# Renders a one-time enrollment token in the response to the POST that created it (DEC-04, P1-D04). The
# plaintext exists only in this response: it is never stored, never redirected through, and the page is
# marked not to be cached, so it cannot be shown again (NFR-1).
module ShowsEnrollmentToken
  private

  def show_token(token, created:)
    response.headers["Cache-Control"] = "no-store"
    @token = token
    @token_record = @host.enrollment_tokens.redeemable.order(created_at: :desc).first
    @created = created
    render "hosts/token", status: (created ? :created : :ok)
  end
end
