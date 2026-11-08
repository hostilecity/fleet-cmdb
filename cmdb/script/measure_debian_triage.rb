# Measures reading and importing a Debian Security Tracker document the size of the real one (P2-S16), without
# committing it: the owner measured https://security-tracker.debian.org/tracker/data/json on 2026-11-07 at
# 88,313,054 bytes, 4,180 source packages, and 79,646 package/CVE entries. The synthetic document has the same
# shape and counts (spec/support/debian_tracker_document.rb). Linux only (peak memory is /proc's VmHWM).
#
#   bin/rails runner script/measure_debian_triage.rb            # generate, then measure each step in its own process
#   bin/rails runner script/measure_debian_triage.rb FILE=json  # measure a real downloaded document instead
#
# Each step runs in a fresh process so its peak is its own: the Rails baseline, DebianTriage::Reader, JSON.parse of
# the whole document (what the reader avoids), and DebianTriage::Import of RELEASES into the database (development's;
# it replaces the triage stored there), with the table's size after it.
require Rails.root.join("spec/support/debian_tracker_document").to_s

# The releases imported: trixie, the one release the MVP fleet reports (only releases hosts report are imported).
# RELEASES=bookworm,trixie measures more.
RELEASES = ENV.fetch("RELEASES", "trixie").split(",")

def peak_mib = File.read("/proc/self/status")[/VmHWM:\s+(\d+)/, 1].to_i / 1024
def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

if (step = ENV["STEP"])
  path = ENV.fetch("DOCUMENT")
  started = clock
  detail =
    case step
    when "baseline" then "-"
    when "reader"
      packages = entries = 0
      DebianTriage::Reader.new(path).each { |p| packages += 1; entries += p.entries&.size.to_i }
      "#{packages} packages, #{entries} entries"
    when "parse" then "#{JSON.parse(File.read(path)).size} packages"
    when "import"
      import = DebianTriage::Import.new(origin: "file", source: File.basename(path), releases: RELEASES, allowed_drops: RELEASES.index_with { 10**9 }) # a rerun may replace everything
                                   .call(DebianTriage::Reader.new(path))
      size = TriageEntry.connection.select_value("SELECT pg_size_pretty(pg_total_relation_size('triage_entries'))")
      "#{import.state}, #{import.counts['releases'].transform_values { |c| c['in_file'] }.to_json} rows, table #{size}"
    end
  puts format("%-9s peak %4d MiB  %6.2f s  %s", step, peak_mib, clock - started, detail)
  exit
end

path = ENV["FILE"]
unless path
  path = Rails.root.join("tmp/debian-tracker-measured.json").to_s
  File.open(path, "wb") { |io| DebianTrackerDocument.write(io, packages: 4_180, entries: 79_646) }
end
puts "#{path}: #{File.size(path)} bytes"
%w[baseline reader parse import].each do |step|
  system({ "STEP" => step, "DOCUMENT" => path }, "bin/rails", "runner", __FILE__, exception: true)
end
