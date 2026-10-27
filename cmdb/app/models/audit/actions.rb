module Audit
  # Every audit action name, in one place (FR-S.3). Later phases add rule changes and task actions.
  module Actions
    HOST_CREATED = "host.created"
    HOST_EDITED = "host.edited"
    HOST_ENROLLED = "host.enrolled"
    HOST_CREDENTIAL_REVOKED = "host.credential_revoked"
    HOST_REENROLLMENT_STARTED = "host.reenrollment_started"
    HOST_RETIRED = "host.retired"
    HOST_ENROLLMENT_TOKEN_ISSUED = "host.enrollment_token_issued"
    OPERATOR_ALLOWED = "operator.allowed"
    OPERATOR_DISALLOWED = "operator.disallowed"
    OPERATOR_SIGNED_IN = "operator.signed_in"

    ALL = constants.map { |name| const_get(name) }.freeze
  end
end
