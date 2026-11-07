# Helpers for fleet compliance specs (P2-D05): CIS results, findings, and evaluations written directly, as the evaluation
# and matching code would leave them, so a spec can build any mix of states quickly and count them again on its own.
module ComplianceHelpers
  # Rules of each severity, n of each, keyed "<severity>-<i>". Returns { severity => [rule, ...] }.
  def compliance_rules(per_severity = 3)
    hashes = FleetCompliance::CIS_SEVERITIES.flat_map do |severity|
      Array.new(per_severity) { |i| cis_rule_hash(key: "#{severity}-#{i}", severity:, title: "#{severity.capitalize} check #{i}") }
    end
    define_cis_rules(*hashes).group_by { |rule| rule.current_version.severity }
  end

  # Current results for one host: results is { rule => "pass" | "fail" | ... }.
  def cis_results!(host, results)
    now = Time.current
    rows = results.map do |rule, result|
      { host_id: host.id, cis_rule_id: rule.id, cis_rule_version_id: (rule.current_version_id unless result == "not_evaluated"), result:,
        evaluated_at: now, changed_at: now }
    end
    CisResult.insert_all!(rows) if rows.any?
  end

  # The host's current config, so the page knows a report arrived.
  def host_config!(host, at: 1.hour.ago)
    HostConfig.create!(host:, facts: {}, content_hash: SecureRandom.hex(32), manifest_version: 1, report_id: SecureRandom.uuid, schema_version: 1,
                       collected_at: at, received_at: at)
  end

  def package_set!(host, at: 1.hour.ago)
    HostPackageSet.create!(host:, manager: "dpkg", package_count: 0, content_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid, schema_version: 1,
                           collected_at: at, received_at: at)
  end

  def vulns_evaluated!(host, state: "evaluated", reason: nil, ecosystem: "Debian:13")
    HostVulnerabilityEvaluation.create!(host:, ecosystem:, state:, reason:, detail: (reason && "Because #{reason}"), evaluated_at: Time.current)
  end

  # Findings for one host: severities is a list such as %w[critical low low]; state open, reopened, or resolved.
  def findings!(host, *severities, state: "open")
    severities.each do |severity|
      advisory = Advisory.create!(advisory_id: "DSA-#{SecureRandom.hex(4)}-1", source: "test", severity:, modified_at: Time.current)
      VulnerabilityFinding.create!(host:, advisory:, package: "acme-#{SecureRandom.hex(3)}", architecture: "amd64", source: "acme", ecosystem: "Debian:13",
                                   installed_version: "1.0-1", state:, first_seen_at: 1.day.ago,
                                   resolution: (state == "resolved" ? "fixed" : nil), resolved_at: (state == "resolved" ? 1.hour.ago : nil))
    end
  end

  # Open CIS failures by severity, counted again from the rows with Ruby, as the Configuration tab picks the severity:
  # the result's rule version, or the rule's current one.
  def expected_cis(host)
    failures = CisResult.where(host_id: host.id, result: "fail").includes(:cis_rule_version, cis_rule: :current_version).map do |result|
      (result.cis_rule_version || result.cis_rule.current_version).severity
    end
    FleetCompliance::CIS_SEVERITIES.index_with { |severity| failures.count(severity) }
  end

  def expected_vulns(host)
    open = VulnerabilityFinding.where(host_id: host.id).includes(:advisory).to_a.reject { |f| f.state == "resolved" }.map { |f| f.advisory.severity }
    Advisory::SEVERITIES.index_with { |severity| open.count(severity) }
  end
end

RSpec.configure do |config|
  config.include ComplianceHelpers
end
