# Content Security Policy for the dashboard (NFR-1, P1-S12). Text from a VM (hostname, OS, mount names,
# warnings) is escaped by the views; this is the second line of defence if markup ever got through:
#
# - Scripts and styles come from this site only, or carry the per-request nonce. The only inline script is the
#   importmap, and Turbo's progress-bar style; both get the nonce from the layout (csp_meta_tag, importmap tags).
#   An injected <script> or an onerror handler has no nonce and does not run.
# - No third-party origins at all: images, fonts, frames, and objects too. Live updates connect back to this
#   host's WebSocket (connect_src 'self' covers it).
# - Forms post to this site, or to Google for sign-in (a form's redirect chain is checked against form-action).
# - The page cannot be framed (clickjacking) and cannot change its base URL.
Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src     :none
    policy.script_src      :self
    policy.style_src       :self
    policy.img_src         :self, :data
    policy.font_src        :self
    policy.connect_src     :self
    policy.manifest_src    :self
    policy.object_src      :none
    policy.frame_src       :none
    policy.frame_ancestors :none
    policy.base_uri        :self
    policy.form_action     :self, "https://accounts.google.com"
  end

  # A fresh random nonce per request, added to the importmap and inline Turbo style via the layout.
  config.content_security_policy_nonce_generator = ->(_request) { SecureRandom.base64(16) }
  config.content_security_policy_nonce_directives = %w[script-src style-src]
end
