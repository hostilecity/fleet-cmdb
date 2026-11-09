# Task output from an agent, made safe to store (P3-S04, threat model O1 to O5). Output is untrusted text from a
# VM: it is stored as inert text and rendered escaped (P3-S10), and never copied into logs or audit entries.
#
#   TaskOutput.sanitize(raw) # => TaskOutput::Result(text:, truncated:)
#
# - Invalid UTF-8 is replaced with U+FFFD.
# - CR LF becomes LF. Terminal escape sequences (CSI, OSC, and two-character ones) are removed whole, then every
#   other control character but tab and newline: C0, DEL, and C1. So are the Unicode bidirectional overrides and
#   isolates, which can make text read differently from what it is.
# - Output longer than the limit keeps its start and its end, where errors usually are, with a marker line in
#   place of the middle that says how many bytes were cut; truncated is then true. The result is never longer
#   than the limit, and never splits a character.
module TaskOutput
  # The server's output limit (FR-3.2). P3-S06 (#31) makes it a setting, never above Task::MAX_OUTPUT_BYTES.
  LIMIT_BYTES = 64.kilobytes
  # Room kept for the marker line.
  MARKER_BYTES = 96

  ESCAPE_SEQUENCE = /\e(?:\[[0-?]*[ -\/]*[@-~]|\][^\a\e]*(?:\a|\e\\)?|[ -\/]*[0-~])/
  CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]/

  Result = Data.define(:text, :truncated)

  module_function

  def sanitize(raw, limit: LIMIT_BYTES)
    return Result.new(text: nil, truncated: false) if raw.nil?

    text = raw.dup.force_encoding(Encoding::UTF_8).scrub("�").gsub("\r\n", "\n").gsub(ESCAPE_SEQUENCE, "").gsub(CONTROL, "")
    return Result.new(text:, truncated: false) if text.bytesize <= limit

    Result.new(text: cut_middle(text, limit), truncated: true)
  end

  # The first and last bytes that fit, each trimmed to whole characters, around a marker line.
  def cut_middle(text, limit)
    half = (limit - MARKER_BYTES) / 2
    head = text.byteslice(0, half).scrub("")
    tail = text.byteslice(text.bytesize - half, half).scrub("")
    "#{head}\n[... #{text.bytesize - head.bytesize - tail.bytesize} bytes of output cut here by the server ...]\n#{tail}"
  end
end
