module Backup
  # When the last backup finished (P1-O01). The backup script (ops/backup/backup.sh) touches this file only
  # after the dump and the release files are written, checksummed, and in the backup location, so its
  # modification time is the time of the last complete backup. /health reports unhealthy when it is missing
  # or older than FLEET_BACKUP_MAX_AGE_HOURS, so a backup that stopped running is loud, not silent.
  module Status
    module_function

    def config = Rails.configuration.x.backup

    def last_success_at
      File.mtime(config.status_file)
    rescue SystemCallError
      nil
    end

    def fresh?(now: Time.current)
      last = last_success_at
      last.present? && now - last <= config.max_age
    end
  end
end
