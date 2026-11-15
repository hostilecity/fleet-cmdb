# Rails parses no JSON request bodies into params (NFR-1). Nothing here needs it:
#
# - Dashboard forms are form-encoded or multipart; Rack parses those, within its own size and count limits.
# - The agent API reads its own bodies, size-limited first (AgentApiRequestGuard, Api::V1::BaseController).
#
# Rails' default JSON parser has no size limit, and it runs for any request with a JSON content type before sign-in
# and CSRF are checked: the CSRF check reads params, and so does the 404 page (for the format). A long number in
# such a body becomes a Bignum, which takes time that grows faster than its length and holds the interpreter lock;
# the "Parameters:" log line then converts it back to text, which costs more. A signed-out JSON POST of 1 MB to a
# dashboard path took about 30 seconds of CPU before this, and Puma takes bodies up to 64 MiB (config/puma.rb). Such
# a body is now ignored: params stay empty, so the request is refused like any other without a CSRF token.
ActionDispatch::Request.parameter_parsers = {}
