# Every example gets a backup status file of its own, in a temporary directory (P1-O01).
RSpec.configure do |config|
  config.around do |example|
    backup = Rails.configuration.x.backup
    saved = backup.to_h.slice(:status_file, :max_age)
    Dir.mktmpdir("backup") do |dir|
      backup.status_file = Pathname(dir).join("last_success")
      example.run
    ensure
      saved.each { |key, value| backup.public_send(:"#{key}=", value) }
    end
  end
end
