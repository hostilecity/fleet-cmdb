module Advisories
  # The JSON documents to import from a path (P2-S10): one .json file, every .json file under a directory, or
  # every .json entry of a zip archive (OSV's all.zip). Each is yielded as an Entry with its bytes, or with the
  # problem that stopped it being read (too large, unreadable), which the import reports as a malformed record.
  #
  # Limits keep a hostile or broken input from exhausting the server: each document is read to at most
  # MAX_RECORD_BYTES + 1 bytes whatever its header claims, an archive may hold at most MAX_ENTRIES documents
  # and MAX_TOTAL_BYTES in all, and an archive file may be at most max_archive_bytes. Breaking a limit for the
  # whole input raises Unreadable.
  #
  # Those limits are sized for the scheduled feed and the rake task. A file uploaded on the dashboard (P2-D06) is
  # read with UPLOAD, much lower, so one upload cannot keep a worker busy for long or hold much memory (review of
  # #129): 256 KiB a document, 200,000 documents, and 512 MiB of JSON in all.
  class Reader
    Entry = Data.define(:location, :bytes, :problem)

    # record_bytes: the largest document; entries: the most documents; total_bytes: the most JSON read in all.
    Limits = Data.define(:record_bytes, :entries, :total_bytes) do
      def record_words = record_bytes >= 1.kilobyte && record_bytes < 1.megabyte ? "#{record_bytes / 1.kilobyte} KiB" : "#{record_bytes / 1.megabyte} MiB"

      def total_words = total_bytes >= 1.megabyte && total_bytes < 1.gigabyte ? "#{total_bytes / 1.megabyte} MiB" : "#{total_bytes / 1.gigabyte} GiB"
    end

    MAX_RECORD_BYTES = 2.megabytes
    MAX_ENTRIES = 1_000_000
    MAX_TOTAL_BYTES = 8.gigabytes
    UPLOAD = Limits.new(record_bytes: 256.kilobytes, entries: 200_000, total_bytes: 512.megabytes)
    ZIP_MAGIC = "PK\x03\x04".b

    include Enumerable

    # name: what messages call the input (a download's temporary file is better called by the feed's file name).
    # limits: UPLOAD for a dashboard upload; the feed's limits by default.
    def initialize(path, name: nil, max_archive_bytes: Advisories.config.max_download_bytes, limits: nil)
      @path = Pathname(path)
      @name = name || @path.basename.to_s
      @max_archive_bytes = max_archive_bytes
      @limits = limits || Limits.new(record_bytes: MAX_RECORD_BYTES, entries: MAX_ENTRIES, total_bytes: MAX_TOTAL_BYTES)
    end

    def each(&block)
      return enum_for(:each) unless block

      if @path.directory? then each_in_directory(&block)
      elsif !@path.file? then raise Unreadable, "#{@name} is not a file or directory"
      elsif zip? then each_in_archive(&block)
      else yield read_file(@path, @name)
      end
    end

    private

    def zip? = @path.extname.casecmp?(".zip") || File.binread(@path, 4) == ZIP_MAGIC

    def each_in_directory
      files = @path.glob("**/*.json").select { |file| file.file? && !file.symlink? }.sort
      raise Unreadable, "#{@name} has more than #{@limits.entries} JSON files" if files.size > @limits.entries

      files.each { |file| yield read_file(file, file.relative_path_from(@path).to_s) }
    end

    def read_file(file, location)
      return Entry.new(location:, bytes: nil, problem: "is larger than #{@limits.record_words}") if file.size > @limits.record_bytes

      Entry.new(location:, bytes: file.binread, problem: nil)
    end

    def each_in_archive
      if @path.size > @max_archive_bytes
        raise Unreadable, "#{@name} is larger than #{@max_archive_bytes / 1.megabyte} MiB"
      end

      total = 0
      Zip::File.open(@path.to_s) do |zip|
        entries = zip.entries.select { |entry| entry.file? && entry.name.end_with?(".json") }
        raise Unreadable, "#{@name} has more than #{@limits.entries} JSON files" if entries.size > @limits.entries

        entries.sort_by(&:name).each do |entry|
          entry_result = read_entry(entry)
          # What was decompressed counts even when the entry is refused, so many oversized or broken entries
          # cannot get past the total (review of #103).
          total += entry_result.bytes ? entry_result.bytes.bytesize : @limits.record_bytes + 1
          raise Unreadable, "#{@name} holds more than #{@limits.total_words} of JSON" if total > @limits.total_bytes

          yield entry_result
        end
      end
    rescue Zip::Error
      raise Unreadable, "#{@name} is not a readable zip archive"
    end

    def read_entry(entry)
      location = Record.clean_text(entry.name, 256)
      bytes = entry.get_input_stream { |io| io.read(@limits.record_bytes + 1) } || "".b
      return Entry.new(location:, bytes: nil, problem: "is larger than #{@limits.record_words}") if bytes.bytesize > @limits.record_bytes

      Entry.new(location:, bytes:, problem: nil)
    rescue Zip::Error, Zlib::Error
      Entry.new(location:, bytes: nil, problem: "could not be read from the archive")
    end
  end
end
