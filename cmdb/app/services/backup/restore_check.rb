module Backup
  # The checks of the restore drill (P1-O01, ops/backup/restore-drill.sh), run by `bin/rails backup:verify_restore`
  # against the app booted on the restored scratch database and release directory:
  #
  # - the app answers /up (it booted against the restored database);
  # - hosts and audit entries are present, and not fewer than the backup recorded when it was taken;
  # - every release row has its binary on disk with the recorded size and SHA-256;
  # - the newest release downloads through the agent API and matches its recorded SHA-256.
  #
  # Counts are compared with "at least" because the live server keeps writing while a backup runs, and hosts and
  # audit entries are never deleted. Nothing here writes to the database.
  class RestoreCheck
    Result = Data.define(:lines, :ok) do
      def ok? = ok

      def failures = lines.reject { |line| line.start_with?("ok ") }
    end

    COUNTED = { "hosts" => Host, "audit_entries" => AuditEntry, "agent_releases" => AgentRelease }.freeze

    # expected: {"hosts" => 12, ...} as recorded by backup.sh; keys not given are not compared.
    def initialize(expected: {}, store: Releases.store)
      @expected = expected
      @store = store
      @lines = []
    end

    def call
      check_boot
      COUNTED.each { |name, model| check_count(name, model) }
      AgentRelease.newest_first.each { |release| check_file(release) }
      check_download(AgentRelease.newest_first.first)
      Result.new(lines: @lines, ok: @lines.all? { |line| line.start_with?("ok ") })
    end

    private

    def pass(text) = @lines << "ok   #{text}"

    def fail_with(text) = @lines << "FAIL #{text}"

    def check(text, passed) = passed ? pass(text) : fail_with(text)

    def session
      @session ||= ActionDispatch::Integration::Session.new(Rails.application).tap do |session|
        session.https!
        session.host! HostSeparation.agent_host
      end
    end

    def check_boot
      session.get "/up"
      check "the app boots against the restored database (/up answers #{session.response.status})", session.response.status == 200
    end

    def check_count(name, model)
      count = model.count
      minimum = Integer(@expected.fetch(name, 0))
      # Hosts and audit entries must exist for the drill to mean anything; releases may legitimately be none.
      required = name == "agent_releases" ? minimum : [ minimum, 1 ].max
      check "#{name}: #{count} restored, at least #{required} expected", count >= required
    end

    def check_file(release)
      path = @store.path(release.version, release.target)
      ok = File.size?(path) == release.size && Digest::SHA256.file(path).hexdigest == release.sha256
      check "release #{release.version}: binary on disk with the recorded size and SHA-256", ok
    end

    def check_download(release)
      return pass("no releases to download") unless release

      session.get "/api/v1/releases/#{release.version}/binary"
      ok = session.response.status == 200 && Digest::SHA256.hexdigest(session.response.body) == release.sha256
      check "release #{release.version}: downloads through the agent API and matches its SHA-256", ok
    end
  end
end
