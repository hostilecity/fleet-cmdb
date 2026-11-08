# The areas the Configuration tab groups facts and CIS-aligned checks by (P2-D02, approved mockup host-config.html),
# from a fact key: a check belongs to the area of the fact it inspects. A key that fits no area is "Other".
module ConfigArea
  AREAS = {
    "SSH server" => /\Asshd\./,
    "Login and password policy" => /\A(login_defs|useradd|pwquality)\./,
    "Firewall and updates" => /\A(firewall|auto_updates)\./,
    "Sensitive files" => /\Afile:/,
    "Services and users" => /\A(service:|services\.|users\.)/
  }.freeze
  OTHER = "Other".freeze
  ORDER = (AREAS.keys + [ OTHER ]).freeze

  module_function

  def of(key) = AREAS.find { |_, pattern| pattern.match?(key.to_s) }&.first || OTHER

  # [[area, items], ...] in ORDER, leaving out empty areas; key gives each item's fact key.
  def group(items, &key)
    grouped = items.group_by { |item| of(key.call(item)) }
    ORDER.filter_map { |area| [ area, grouped[area] ] if grouped[area] }
  end
end
