module Enrollment
  # Creates a pending host and its first enrollment token in one transaction (P1-S05).
  # Returns [host, plaintext_token]; the token is shown to the operator once.
  class RegisterHost
    def self.call(attributes, actor:)
      Host.transaction(requires_new: true) do
        host = Host.register!(attributes, actor:)
        [ host, IssueToken.call(host:, actor:) ]
      end
    end
  end
end
