# Nightly check of the partitioned history tables (ADR 0027): they have no foreign keys, so this reports any row
# written since the last check whose host, CIS rule, or rule version does not exist. Hosts are never deleted and every
# writer holds the host's lock, so it should find none. Anything it finds is logged as an error and kept for two days
# (Partitions::ORPHANS_KEY), so /health's partitions check shows a warning and the dashboard's banner names it.
class PartitionCheckJob < ApplicationJob
  def perform
    found = Partitions.orphans
    Rails.cache.write(Partitions::ORPHANS_KEY, found, expires_in: 2.days)
    if found.any?
      logger.error("[partitions] rows with no matching host or rule: #{found.map { |column, count| "#{column}=#{count}" }.join(' ')}")
    else
      logger.info("[partitions] check: no rows without their host or rule")
    end
    found
  end
end
