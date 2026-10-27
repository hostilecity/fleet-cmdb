# Operator allowlist (FR-S.4, DEC-06). The first operator is added here; there is no sign-up. Changes are
# audited with the system actor.
namespace :operators do
  desc "Allow a Google account to sign in: EMAIL=someone@example.com"
  task allow: :environment do
    email = ENV.fetch("EMAIL") { abort "Usage: bin/rails operators:allow EMAIL=someone@example.com" }
    entry = OperatorAllowlistEntry.allow!(email, actor: Audit::SYSTEM)
    puts "Allowed #{entry.email}."
  rescue ActiveRecord::RecordInvalid => e
    abort "Not allowed: #{e.record.errors.full_messages.to_sentence}"
  end

  desc "Remove a Google account from the allowlist (signs it out on its next request): EMAIL=..."
  task disallow: :environment do
    email = ENV.fetch("EMAIL") { abort "Usage: bin/rails operators:disallow EMAIL=someone@example.com" }
    abort "#{email} is not on the allowlist." unless OperatorAllowlistEntry.disallow!(email, actor: Audit::SYSTEM)
    puts "Removed #{OperatorAllowlistEntry.normalize(email)}."
  end

  desc "List the allowlist and when each operator last signed in"
  task list: :environment do
    operators = Operator.all.index_by(&:email)
    entries = OperatorAllowlistEntry.order(:email)
    puts "The allowlist is empty. Add the first operator with operators:allow EMAIL=..." if entries.none?
    entries.each do |entry|
      last = operators[entry.email]&.last_signed_in_at
      puts "#{entry.email}  #{last ? "last signed in #{last.utc.iso8601}" : 'never signed in'}"
    end
  end
end
