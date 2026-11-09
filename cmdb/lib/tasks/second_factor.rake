# The lost-authenticator recovery (P3-S09, ADR 0006): only from the server console, never from the web, so someone who
# took over an operator's Google session cannot reset the factor too. Audited with the system as the actor.
namespace :second_factor do
  desc "Remove an operator's authenticator and recovery codes, so they can set up a new one: EMAIL=someone@example.com"
  task :reset, [ :email ] => :environment do |_task, args|
    email = args[:email].presence || ENV["EMAIL"].presence or abort "Usage: bin/rails second_factor:reset EMAIL=someone@example.com"
    operator = SecondFactors.reset!(email)
    puts "Reset the second factor of #{operator.email}. They can set up a new one under Settings, Your second factor."
  rescue SecondFactors::NotEnrolled => e
    abort "Nothing reset: #{e.message}."
  end
end
