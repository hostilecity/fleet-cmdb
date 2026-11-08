# DebianTrackerDocument writes a synthetic document of any size in the same shape, for the reader's specs and
# for script/measure_debian_triage.rb, which measures the real file's size (88,313,054 bytes, 4,180 source
# packages, 79,646 package/CVE entries) without committing it. It needs only the standard library.
require "json"

module DebianTrackerDocument
  RELEASES = %w[bullseye bookworm trixie forky sid].freeze
  SUITES = { "bullseye" => "bullseye-security", "bookworm" => "bookworm-security", "trixie" => "trixie-security", "forky" => "forky", "sid" => "sid" }.freeze
  URGENCIES = [ "not yet assigned", "unimportant", "low", "medium", "high", "low*", "medium**", "end-of-life" ].freeze
  WORDS = %w[buffer overflow in the parser allows remote attackers to cause a denial of service or possibly execute arbitrary code via
             crafted input heap use-after-free out-of-bounds read integer overflow when processing certain files local users
             obtain sensitive information NULL pointer dereference memory leak race condition].freeze

  module_function

  # Writes { package => { CVE => entry } } to io, one package at a time (so it never holds the document),
  # with entries spread over packages as the real file's are: a few packages hold thousands (the kernel), most a
  # handful. Deterministic for a seed. Returns the number of entries written. other_ids: every nth entry has a
  # TEMP- id instead of a CVE id.
  def write(io, packages:, entries:, seed: 1, other_ids: 40)
    random = Random.new(seed)
    sizes = spread(packages, entries, random)
    io.write("{")
    number = 0
    sizes.each_with_index do |size, index|
      io.write(",") unless index.zero?
      io.write("#{JSON.generate(index.zero? ? 'linux' : "pkg#{index}")}:{")
      size.times do |i|
        number += 1
        id = (number % other_ids).zero? ? format("TEMP-%07d-%06X", number, number) : format("CVE-%d-%d", 1999 + (number % 28), 10_000 + number)
        io.write(",") unless i.zero?
        io.write("#{JSON.generate(id)}:#{JSON.generate(entry(random, number))}")
      end
      io.write("}")
    end
    io.write("}")
    sizes.sum
  end

  def spread(packages, entries, random)
    big = [ entries / 10, 1 ].max
    rest = entries - big
    weights = Array.new(packages - 1) { random.rand**3 + 0.01 }
    total = weights.sum
    sizes = weights.map { |w| [ (rest * w / total).floor, 1 ].max }
    sizes[0] += rest - sizes.sum # what rounding left
    [ big, *sizes ]
  end

  def entry(random, number)
    version = "#{random.rand(1..9)}.#{random.rand(0..40)}-#{random.rand(1..12)}"
    releases = RELEASES.to_h do |release|
      status = %w[open resolved resolved resolved undetermined].sample(random:)
      data = { "status" => status, "repositories" => { SUITES.fetch(release).delete_suffix("-security") => "#{version}+#{release}1" } }
      data["fixed_version"] = status == "resolved" ? (random.rand < 0.2 ? "0" : "#{version}+#{release}2") : nil
      data["urgency"] = URGENCIES.sample(random:)
      if status == "open" && random.rand < 0.5
        data["nodsa"] = [ "Minor issue", "Can be fixed via point release", "" ].sample(random:)
        data["nodsa_reason"] = [ "", "postponed", "ignored" ].sample(random:)
      end
      data["next_point_update"] = true if status == "open" && random.rand < 0.1
      [ release, data.compact ]
    end
    { "description" => Array.new(random.rand(55..71)) { WORDS.sample(random:) }.join(" ").capitalize,
      "debianbug" => (number.even? ? 1_000_000 + number : nil), "scope" => %w[local remote].sample(random:), "releases" => releases }.compact
  end
end
