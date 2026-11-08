# A source package an advisory affects in one ecosystem, with the version ranges it is affected in (P2-S10,
# DEC-11). ranges holds each OSV ECOSYSTEM range's events as published; matching (P2-S11) compares an
# installed version to them with the ecosystem's package manager order.
class AdvisoryPackage < ApplicationRecord
  belongs_to :advisory
end
