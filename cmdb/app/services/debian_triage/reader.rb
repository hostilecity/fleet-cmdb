require "strscan"

module DebianTriage
  # Reads the Debian Security Tracker's JSON document (P2-S16) one source package at a time, in bounded memory.
  #
  # The document is one object, { "<source package>" => { "<CVE id>" => { ..., "releases" => { ... } } } },
  # 84.2 MiB when measured (cmdb/README.md). Parsing it whole with JSON.parse holds every entry as Ruby objects
  # at once, so this reader scans the top level itself, a chunk at a time, and parses each package's value on its
  # own: memory is bounded by the largest package, not the document. The scan only matches braces and brackets
  # outside strings; each value is still parsed by JSON.parse, so it validates the JSON it yields.
  #
  # Limits: the file at most max_bytes, a package's value at most MAX_PACKAGE_BYTES, and at most MAX_NESTING
  # levels inside a package's value (package, CVE, release map, release, repositories). A package whose value
  # cannot be parsed, or is not an object, is yielded with its problem, and the import counts it as malformed.
  # Anything that breaks the document's own structure (truncation, a broken key, data after the end) or a limit
  # raises Advisories::Unreadable, and nothing is imported.
  class Reader
    # package: the key; entries: the package's Hash of CVE id => entry, or nil when problem says why not.
    Package = Data.define(:package, :entries, :problem)

    CHUNK = 1.megabyte
    COMPACT_AT = 8.megabytes
    MAX_PACKAGE_BYTES = 64.megabytes
    MAX_NESTING = 5
    WHITESPACE = /[ \t\r\n]*/n
    STRUCTURE = /["{}\[\]]/n
    STRING_END = /["\\]/n
    SCALAR_END = /[ \t\r\n,}]/n

    include Enumerable

    def initialize(path, name: nil, max_bytes: DebianTriage.config.max_download_bytes)
      @path = Pathname(path)
      @name = name || @path.basename.to_s
      @max_bytes = max_bytes
    end

    def each(&block)
      return enum_for(:each) unless block
      raise Advisories::Unreadable, "#{@name} is not a file" unless @path.file?
      raise Advisories::Unreadable, "#{@name} is larger than #{@max_bytes / 1.megabyte} MiB" if @path.size > @max_bytes

      @path.open("rb") do |io|
        @io = io
        @scanner = StringScanner.new(+"".b)
        read_document(&block)
      end
    end

    private

    def read_document
      skip_whitespace
      expect!("{")
      skip_whitespace
      return expect!("}") && finish if peek == "}"

      loop do
        @start = @scanner.pos
        expect!('"')
        skip_string
        key = slice(@start)
        skip_whitespace
        expect!(":")
        skip_whitespace
        value_start = @scanner.pos
        skip_value
        yield package(key, slice(value_start))
        skip_whitespace
        separator = next_byte
        break if separator == "}"
        raise unreadable("has #{separator.inspect} where a comma or the end of the document belongs") unless separator == ","

        compact
        @start = @scanner.pos
        skip_whitespace
      end
      finish
    end

    def finish
      skip_whitespace
      raise unreadable("has data after the end of the document") unless @scanner.eos?
    end

    def package(key, value)
      name = JSON.parse(key.force_encoding(Encoding::UTF_8))
      entries = JSON.parse(value.force_encoding(Encoding::UTF_8), max_nesting: MAX_NESTING)
      return Package.new(package: name, entries: nil, problem: "is not an object") unless entries.is_a?(Hash)

      Package.new(package: name, entries:, problem: nil)
    rescue JSON::NestingError
      Package.new(package: name, entries: nil, problem: "is nested more than #{MAX_NESTING} levels deep")
    rescue JSON::ParserError, EncodingError
      raise unreadable("has a source package name that is not a valid JSON string") if name.nil?

      Package.new(package: name, entries: nil, problem: "is not valid JSON")
    end

    def slice(from) = @scanner.string.byteslice(from, @scanner.pos - from)

    # An object or array (braces and brackets matched outside strings), a string, or a bare scalar.
    def skip_value
      case peek
      when "{", "[" then skip_container
      when '"'
        next_byte
        skip_string
      else
        skip_until(SCALAR_END)
        @scanner.pos -= 1 # the terminator belongs to the document
      end
    end

    def skip_container
      depth = 0
      loop do
        skip_until(STRUCTURE)
        case @scanner.string.getbyte(@scanner.pos - 1)
        when 0x22 then skip_string # "
        when 0x7B, 0x5B then depth += 1 # { [
        else
          depth -= 1
          break if depth.zero?
        end
      end
    end

    # After the opening quote: to just past the closing one, stepping over escapes.
    def skip_string
      loop do
        skip_until(STRING_END)
        break if @scanner.string.getbyte(@scanner.pos - 1) == 0x22

        next_byte # the escaped character
      end
    end

    # Past the next match of pattern, reading more as needed. Bytes before a match are never structure, so what was
    # scanned without one is not scanned again.
    def skip_until(pattern)
      until @scanner.skip_until(pattern)
        @scanner.terminate
        check_package_size!
        raise unreadable("ends in the middle of the document") unless fill
      end
      check_package_size!
    end

    def skip_whitespace
      @scanner.skip(WHITESPACE)
      while @scanner.eos? && fill
        @scanner.skip(WHITESPACE)
        check_package_size!
      end
    end

    def peek
      raise unreadable("ends in the middle of the document") if @scanner.eos? && !fill

      @scanner.peek(1)
    end

    def next_byte = peek.tap { @scanner.pos += 1 }

    def expect!(char)
      found = next_byte
      raise unreadable("has #{found.inspect} where #{char.inspect} belongs") unless found == char

      true
    end

    def fill
      chunk = @io.read(CHUNK) or return false
      @scanner << chunk
      true
    end

    def check_package_size!
      return unless @start && @scanner.pos - @start > MAX_PACKAGE_BYTES

      raise unreadable("has a source package larger than #{MAX_PACKAGE_BYTES / 1.megabyte} MiB")
    end

    # Drops what was read already, between packages, so the buffer holds about one package and one chunk.
    def compact
      return if @scanner.pos < COMPACT_AT

      @scanner = StringScanner.new(@scanner.rest)
    end

    def unreadable(problem) = Advisories::Unreadable.new("#{@name} #{problem}, so nothing was imported")
  end
end
