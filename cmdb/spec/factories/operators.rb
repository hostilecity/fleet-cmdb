FactoryBot.define do
  factory :operator do
    sequence(:email) { |n| "operator#{n}@example.com" }
    sequence(:google_uid) { |n| (1_000_000_000_000 + n).to_s }
    name { "Example Operator" }
  end
end
