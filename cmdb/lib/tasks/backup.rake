# The verification half of the restore drill (P1-O01). ops/backup/restore-drill.sh restores a backup into a scratch
# database and release directory, then runs this against them.
namespace :backup do
  desc "Check a restored database and release directory: COUNTS=<file of name=count lines from the backup> (optional)"
  task verify_restore: :environment do
    expected = ENV["COUNTS"].present? ? File.readlines(ENV["COUNTS"], chomp: true).filter_map { |line| line.split("=", 2) if line.include?("=") }.to_h : {}
    result = Backup::RestoreCheck.new(expected:).call
    puts result.lines
    abort "Restore drill FAILED: #{result.failures.size} check(s) did not pass." unless result.ok
    puts "Restore drill passed."
  end
end
