# Deletes rules file previews past their 15 minutes (P2-D06, RuleImportPreview). An expired preview is refused
# whether or not this has run yet; this only keeps the uploaded files from being kept longer than promised.
class RuleImportPreviewPruneJob < ApplicationJob
  def perform(now: Time.current)
    deleted = RuleImportPreview.prune!(now)
    logger.info("[rules] pruned #{deleted} expired rules file previews") if deleted.positive?
    deleted
  end
end
