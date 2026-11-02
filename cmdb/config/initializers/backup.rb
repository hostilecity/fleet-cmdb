# Backup freshness (P1-O01). ops/backup/backup.sh touches the status file after each complete backup; the volume
# holding it is shared with the server container so /health can see it.
Rails.application.configure do
  backup = config.x.backup

  backup.status_file ||= Pathname(ENV.fetch("FLEET_BACKUP_STATUS_FILE") { Rails.root.join("storage/backup/last_success").to_s }).expand_path
  # A daily backup plus slack for a slow run.
  backup.max_age ||= Float(ENV.fetch("FLEET_BACKUP_MAX_AGE_HOURS", "26")).hours
end
