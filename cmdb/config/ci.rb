# Run using bin/ci

CI.run do
  step "Setup", "bin/setup --skip-server"

  # In GitHub Actions, offenses also become annotations on the pull request.
  step "Style: Ruby", "bin/rubocop#{' --format progress --format github' if ENV['GITHUB_ACTIONS']}"

  step "Security: Gem audit", "bin/bundler-audit"
  step "Security: Importmap vulnerability audit", "bin/importmap audit"
  step "Security: Brakeman code analysis", "bin/brakeman --quiet --no-pager --exit-on-warn --exit-on-error"

  # Every line of app/ and lib/ must run in the suite: below 100% line coverage, RSpec exits non-zero.
  step "Tests: RSpec", "COVERAGE_MINIMUM=100 bundle exec rspec"


  # Optional: set a green GitHub commit status to unblock PR merge.
  # Requires the `gh` CLI and `gh extension install basecamp/gh-signoff`.
  # if success?
  #   step "Signoff: All systems go. Ready for merge and deploy.", "gh signoff"
  # else
  #   failure "Signoff: CI failed. Do not merge or deploy.", "Fix the issues and try again."
  # end
end
