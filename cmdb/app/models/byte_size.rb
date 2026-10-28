# Binary byte sizes as free and df show them: 34359738368 -> "32 GiB".
module ByteSize
  UNITS = %w[bytes KiB MiB GiB TiB PiB].freeze

  module_function

  def format(bytes)
    return nil if bytes.nil?

    exponent = bytes.zero? ? 0 : [ (Math.log(bytes) / Math.log(1024)).floor, UNITS.size - 1 ].min
    return "#{bytes} bytes" if exponent.zero?

    value = bytes.to_f / (1024**exponent)
    "#{value.round(value < 10 ? 1 : 0).to_s.delete_suffix('.0')} #{UNITS[exponent]}"
  end
end
