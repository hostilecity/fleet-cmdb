# Builds GitHub Actions workflow commands for error annotations (#69). Annotations show on the pull request
# and can be read through the checks API, where job logs cannot. Used by bin/ci and the RSpec formatter only;
# the application never loads it (lib/ci is not autoloaded).
#
# https://docs.github.com/actions/reference/workflow-commands-for-github-actions#setting-an-error-message
module GithubAnnotation
  module_function

  def active? = ENV["GITHUB_ACTIONS"] == "true"

  # "::error file=...,line=...,title=...::message", with every value escaped so a message can never end the
  # command early or inject a second one.
  def error(message, title:, file: nil, line: nil)
    properties = { file:, line:, title: }.compact.map { |key, value| "#{key}=#{escape_property(value.to_s)}" }
    "::error #{properties.join(',')}::#{escape_data(message.to_s)}"
  end

  def escape_data(text) = text.gsub("%", "%25").gsub("\r", "%0D").gsub("\n", "%0A")

  def escape_property(text) = escape_data(text).gsub(":", "%3A").gsub(",", "%2C")
end
