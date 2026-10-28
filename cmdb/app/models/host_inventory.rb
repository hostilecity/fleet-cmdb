# A host's current inventory (FR-1.3): stable and volatile fields from the latest report, with the
# collection warnings that came with it. Volatile fields change on every report; a change to the stable
# fields also creates an InventorySnapshot.
class HostInventory < ApplicationRecord
  belongs_to :host
end
