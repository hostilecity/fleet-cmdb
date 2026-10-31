module Releases
  # Release binaries on disk (FLEET_RELEASES_DIR, a persistent volume), one file per release named as the
  # release workflow names it. A binary is written to a staging file in the same directory and renamed into
  # place only once it has been verified, so a reader never sees a partial file.
  class Store
    attr_reader :dir

    def initialize(dir)
      @dir = Pathname(dir)
    end

    def path(version, target = TARGET) = dir.join(Releases.binary_name(version, target))

    # Yields a new, empty staging file opened for writing and returns its path. The file is removed if the
    # block raises.
    def stage
      FileUtils.mkdir_p(dir, mode: 0o750)
      file = Tempfile.create([ ".incoming-", ".part" ], dir)
      begin
        file.binmode
        yield file
        file.flush
        file.fsync
        Pathname(file.path)
      ensure
        file.close
      end
    rescue StandardError
      File.unlink(file.path) if file && File.exist?(file.path)
      raise
    end

    # Moves a verified staging file to its release path, atomically.
    def install(staged, version, target = TARGET)
      File.rename(staged, path(version, target))
      File.open(dir) { |handle| handle.fsync } # so the rename itself survives a crash
    end

    def discard(staged)
      File.unlink(staged) if staged && File.exist?(staged)
    end
  end
end
