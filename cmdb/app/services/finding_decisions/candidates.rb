module FindingDecisions
  # The hosts a decision on one advisory may cover, each with its own evidence (N8: "each host shows its own
  # evidence"), loaded in a fixed number of queries for the hosts given:
  #
  # - its open findings of the advisory (every binary package it matches there) and the bucket and rule they are in
  #   (the worst: Needs attention before Low risk, then the rule's order);
  # - whether a process holding a listening socket loads one of those packages (VT-APPLICABILITY's evidence, through
  #   VulnerabilityTriage::Explain), and whether its firewall is enabled (its config report's firewall.enabled);
  # - its active decision for the advisory, if any;
  # - and why it cannot be chosen (problem), or nil: no open finding, a finding not triaged yet, one in Fix available
  #   (upgrade instead), none in Needs attention or Low risk, or an active decision already.
  #
  # others lists other hosts in the fleet with the same open finding, at most OTHERS: read from the findings' advisory
  # index with a limit and no sort, so an advisory every host has costs the same as one on two hosts.
  class Candidates
    OTHERS = FindingDecisions::MAX_HOSTS - 1
    # Rows read to find OTHERS other hosts (an advisory matches a few binary packages per host).
    OTHER_ROWS = OTHERS * 8
    LISTENING = { "network" => "listening on the network", "loopback" => "listening on loopback only", "none" => "no listener reported" }.freeze

    Candidate = Data.define(:host, :findings, :rule, :listening, :firewall, :decision, :problem, :signals) do
      def bucket = rule && VulnerabilityTriage::RULES.fetch(rule)
      def packages = findings.map(&:package).uniq.sort

      # The evidence a decision keeps (VT-S06): bucket and rule, severity, KEV, EPSS band, attack vector, listening class.
      def evidence
        { "bucket" => bucket, "rule" => rule, "severity" => signals.severity, "kev" => signals.kev?, "kev_cves" => signals.kev_cves,
          "epss_band" => signals.epss_band, "epss_score" => signals.epss_score&.to_d&.round(4)&.to_s("F"),
          "attack_vector" => VulnerabilityTriage::Reasons.vector_text(signals.cvss_av, signals.cvss_pr, signals.cvss_ui),
          "listening" => listening, "firewall" => firewall }
      end
    end

    # Up to OTHERS other in-fleet host ids with an open finding of the advisory, besides except.
    def self.other_host_ids(advisory, except:)
      VulnerabilityFinding.where(advisory_id: advisory.id, state: %w[open reopened]).where.not(host_id: except).limit(OTHER_ROWS).pluck(:host_id).uniq
                          .then { |ids| Host.in_fleet.where(id: ids).order(:id).limit(OTHERS).pluck(:id) }
    end

    # [Candidate] for the hosts, in the order given; retired hosts are left out.
    def self.load(advisory, host_ids, signals: nil) = new(advisory, host_ids, signals).list

    attr_reader :list

    def initialize(advisory, host_ids, signals)
      @signals = signals || FindingDecisions.signals([ advisory.id ]).fetch(advisory.id)
      hosts = Host.in_fleet.where(id: host_ids).index_by(&:id)
      findings = VulnerabilityFinding.with_details.active.where(host_id: hosts.keys, advisory_id: advisory.id).order(:package, :architecture).to_a
      inputs = VulnerabilityTriage::Explain.load(findings)
      by_host = findings.group_by(&:host_id)
      decisions = FindingDecision.active.where(host_id: hosts.keys, advisory_id: advisory.id).index_by(&:host_id)
      firewalls = firewalls(hosts.keys)
      @list = host_ids.filter_map do |id|
        host = hosts[id] or next
        list = by_host.fetch(id, [])
        rule = worst_rule(list)
        Candidate.new(host:, findings: list, rule:, listening: listening(list, inputs), firewall: firewalls[id], decision: decisions[id],
                      problem: problem(list, rule, decisions[id]), signals: @signals)
      end
    end

    private

    def worst_rule(findings)
      rules = findings.filter_map { |f| VulnerabilityTriage.rule_for(f.bucket_rule) }.select { |r| FindingDecisions::ALLOWED_BUCKETS.include?(VulnerabilityTriage::RULES[r]) }
      rules.min_by { |r| [ VulnerabilityTriage::RULES[r] == "attention" ? 0 : 1, VulnerabilityTriage::RULE_IDS.fetch(r) ] }
    end

    def problem(findings, rule, decision)
      return "it has no open finding for this advisory." if findings.empty?
      return "its findings are not triaged yet; try again in a few minutes." if findings.any? { |f| f.bucket.nil? }
      return "a fix is available for it on this host: upgrade instead." if findings.any? { |f| VulnerabilityTriage.bucket_for(f.bucket) == "fix" }
      return "its findings are Ignorable here, so there is nothing to decide." if rule.nil?
      return "it already has a decision for this advisory: change or end that one." if decision

      nil
    end

    # "network", "loopback", or "none" (no listener reported, which never means nothing listens).
    def listening(findings, inputs)
      listeners = findings.filter_map { |f| inputs[f.id]&.listener }
      return "none" if listeners.empty?

      listeners.any?(&:network) ? "network" : "loopback"
    end

    # { host id => true or false } from each host's last config report, when it read the fact.
    def firewalls(ids)
      HostConfig.where(host_id: ids).pluck(:host_id, Arel.sql("facts #>> '{firewall.enabled,state}'"), Arel.sql("facts #>> '{firewall.enabled,value}'"))
                .filter_map { |id, state, value| [ id, value == "true" ] if state == "ok" && %w[true false].include?(value) }.to_h
    end
  end
end
