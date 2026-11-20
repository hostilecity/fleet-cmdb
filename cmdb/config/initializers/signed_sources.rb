# Debian's signed-template source packages, matched as the source the advisories name (#270, SignedSources): the
# table in config/signed_sources.yml, checked once the application has loaded, so a mistake stops the server from
# starting rather than leaving the running kernel without findings.
Rails.application.config.after_initialize do |app|
  app.config.x.signed_sources = SignedSources.load(Rails.root.join("config/signed_sources.yml"))
end
