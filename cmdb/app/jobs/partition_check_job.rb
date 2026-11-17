# Nightly check of the partitioned history tables (ADR 0027): they have no foreign keys, so this reports any row
# written since the last check whose host, CIS rule, or rule version does not exist. Hosts are never deleted and every
# writer holds the host's lock, so it should find none; anything it finds is logged as an error.
class PartitionCheckJob < ApplicationJob
  def perform
    found = Partitions.orphans
    if found.any?
      logger.error("[partitions] rows with no matching host or rule: #{found.map { |column, count| "#{column}=#{count}" }.join(' ')}")
    else
      logger.info("[partitions] check: no rows without their host or rule")
    end
    found
  end
end
