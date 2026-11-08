# Helpers for the Debian Security Tracker's triage (P2-S16). spec/fixtures/debian_tracker holds hand-written
# documents in the shape https://security-tracker.debian.org/tracker/data/json publishes; their CVE numbers,
# bug numbers, and descriptions are made up except where a spec says it follows the owner's example
# (CVE-2026-19499 in glibc, 2026-11-07). DebianTrackerDocument (debian_tracker_document.rb) writes large ones.
module DebianTrackerHelpers
  FIXTURES = Rails.root.join("spec/fixtures/debian_tracker")

  # A tracker document: a Hash (written as JSON) or a String (written as it is), in a temporary file.
  def tracker_file(document, name: "json")
    dir = Pathname(Dir.mktmpdir("debian-tracker-"))
    @osv_dirs = [ *@osv_dirs, dir ]
    dir.join(name).tap { |path| path.write(document.is_a?(String) ? document : JSON.generate(document)) }
  end

  # One release's data as the tracker publishes it.
  def tracker_release(status: "open", urgency: "not yet assigned", repositories: { "trixie" => "2.41-12+deb13u4" }, **extra)
    { "status" => status, "repositories" => repositories, "urgency" => urgency }.merge(extra.transform_keys(&:to_s))
  end

  # { package => { cve => releases } } as a document whose entries have a description and scope.
  def tracker_document(packages)
    packages.transform_values do |cves|
      cves.transform_values { |releases| { "description" => "made-up issue", "scope" => "remote", "releases" => releases } }
    end
  end

  def import_triage(document, origin: "file", source: "json", **)
    DebianTriage::Import.new(origin:, source:, **).call(DebianTriage::Reader.new(document.is_a?(Pathname) ? document : tracker_file(document)))
  end
end

# A release table for a group: triage_releases: { ["debian", "13"] => "trixie" }.
RSpec.shared_context "triage releases" do
  around do |example|
    saved = DebianTriage.config.releases
    DebianTriage.config.releases = example.metadata[:triage_releases]
    example.run
  ensure
    DebianTriage.config.releases = saved
  end
end

RSpec.configure do |config|
  config.include DebianTrackerHelpers
  config.include_context "triage releases", :triage_releases
end
