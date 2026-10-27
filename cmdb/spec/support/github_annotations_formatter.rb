# Emits a GitHub Actions error annotation for each failing example, so failures show on the pull request
# and through the checks API without reading the job log.
class GithubAnnotationsFormatter
  RSpec::Core::Formatters.register self, :example_failed

  def initialize(output)
    @output = output
  end

  def example_failed(notification)
    example = notification.example
    location = example.location.delete_prefix("./").split(":")
    message = "#{example.full_description}\n\n#{notification.message_lines.join("\n")}".strip
    @output.puts "::error file=cmdb/#{location.first},line=#{location.last},title=#{escape_property(example.full_description)}::#{escape_data(message)}"
  end

  private

  def escape_data(text) = text.gsub("%", "%25").gsub("\r", "%0D").gsub("\n", "%0A")

  def escape_property(text) = escape_data(text).gsub(":", "%3A").gsub(",", "%2C")
end
