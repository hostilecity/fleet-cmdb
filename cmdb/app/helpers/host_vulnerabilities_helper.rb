# Display helpers for the Vulnerabilities tab and one package's findings (P2-D04, approved mockups host-vulns.html,
# host-vuln-package.html, states-packages-vulns.html). Advisory text comes from an outside source and package data
# from an agent: both pass through Rails' escaping. A link to the source advisory is drawn only for an http or https
# URL with a host, and always opens with rel="noopener noreferrer".
module HostVulnerabilitiesHelper
  RESOLUTIONS = {
    "fixed" => "Fixed: the installed version is outside the affected ranges", "removed" => "Removed: package no longer installed",
    "withdrawn" => "Withdrawn: the advisory was withdrawn by its source", "not_affected" => "Not affected: the advisory no longer names this package"
  }.freeze
  # What each reason for not evaluating means for the operator, after the server's own sentence (HostContext).
  NEXT_STEPS = {
    "no_inventory" => "It is evaluated as soon as the agent sends its first inventory and package reports.",
    "unmapped_distribution" => "Adding a distribution needs a new decision; until then its packages are listed but not matched.",
    "no_package_report" => :request_packages,
    "unsupported_package_manager" => "Packages and vulnerabilities cannot be shown for this host.",
    "unreadable_packages" => "Its findings are matched again after the next package report that can be read; request one on the Packages tab.",
    "no_advisory_data" => :failed_jobs
  }.freeze

  def finding_state_lamp(finding)
    case finding.state
    when "resolved" then tag.span("Resolved", class: "lamp online")
    when "reopened" then tag.span("Reopened", class: "lamp fail")
    else tag.span("Open", class: "lamp fail")
    end
  end

  # The advisory id, linked to the source advisory when it has a web address, with its summary.
  def advisory_cell(advisory)
    url = web_url(advisory.reference_url)
    id = url ? link_to(advisory.advisory_id, url, rel: "noopener noreferrer", target: "_blank") : tag.span(advisory.advisory_id, class: "mono")
    safe_join([ id, (tag.span("No link recorded", class: "state-note") unless url), (tag.span(advisory.summary, class: "state-note") if advisory.summary.present?),
                (tag.span("The source gave no severity.", class: "state-note") if advisory.severity == "unknown") ].compact)
  end

  # The URL when it is http or https with a host and no whitespace or control characters; nil otherwise.
  def web_url(url)
    return nil unless url.is_a?(String) && !url.match?(/[[:space:][:cntrl:]]/)

    uri = URI.parse(url)
    url if %w[http https].include?(uri.scheme&.downcase) && uri.host.present?
  rescue URI::InvalidURIError
    nil
  end

  # A backport's (#274): a fix only the release it is built from records is shown but is not a fix for this release,
  # unless a backport at or above it is installed (K1, as its reason says), and a kept finding says why it is open.
  def fixed_in(finding)
    if finding.fixed_version then safe_join([ "Fixed in ", tag.span(finding.fixed_version, class: "mono") ])
    elsif finding.from_fixed_version && finding.bucket_rule == VulnerabilityTriage::RULE_IDS.fetch("K1")
      safe_join([ "Fixed in ", tag.span(finding.from_fixed_version, class: "mono"), ", which is installed (a backport at or above it)" ])
    elsif finding.from_fixed_version
      tag.span(safe_join([ "Fixed in ", tag.span(finding.from_fixed_version, class: "mono"), " in the release this backport is built from; no backport of it known yet" ]),
               class: "unavailable")
    elsif finding.kept then tag.span("Kept open: only this release's data says it is fixed", class: "unavailable")
    else tag.span("No fix available", class: "unavailable")
    end
  end

  # A package row's fix count (HostFindingGroups::Group): how many of its findings have a known fixed version for the
  # host's release, never "N findings" alone (owner request). Whether that version is in the host's repositories yet
  # is not known to the server.
  def fixable_count(group)
    fixable, total = group.fixable, group.total
    if fixable.zero? then tag.span(total == 1 ? "No fix available" : "No fix for any of #{total}", class: "unavailable")
    elsif fixable == total then total == 1 ? "Fix available" : "Fix for all #{total}"
    else "Fix for #{fixable} of #{total}"
    end
  end

  # Debian's versioned kernel image package names (linux-image-<release>, -unsigned, -dbg), which are never upgraded in
  # place: the fix is a new package, and the old image keeps its findings until it is removed. Not the
  # linux-image-<arch> metapackages (linux-image-amd64, linux-image-cloud-amd64): once they carry findings (#272),
  # apt upgrade clears them, so "remove this old image" would be wrong advice (review of #272, item 3). A pattern here until VT-BUCKETS brings
  # the per-distribution applicability table (cmdb/config/triage_applicability.yml) with the kernel rules K1 and K2,
  # which replace this note with a work item. The signed images and the metapackages, built from linux-signed-<arch>,
  # are matched as linux since #270, so the signed images get this note too.
  KERNEL_IMAGE = /\Alinux-image-\d/

  # Under a kernel image package with an open finding that has a fix (VT-FIXABLE #256, the spec's intro): until
  # VT-BUCKETS, a running kernel's fix shows as "Fix available" on its package row, but in Debian each kernel update is
  # a new binary package. apt-get upgrade and the update task (apply_package_updates, DEC-16: Upgrade-Allow-New=false)
  # never install it; apt upgrade does, as a dependency of the linux-image-<arch> metapackage, and apt full-upgrade
  # also may remove packages. It fixes nothing until the host boots it, and this versioned image keeps its findings
  # until it is removed. nil for any other package, or with no fix.
  def kernel_fix_note(package, fixable)
    return nil unless fixable.positive? && KERNEL_IMAGE.match?(package)

    tag.span(safe_join([ "A kernel fix comes in a new package, which ", tag.code("apt-get upgrade"), " and the update task don't install: install it with ",
                         tag.code("apt upgrade"), " (or ", tag.code("apt full-upgrade"), " where that holds it back; it can also remove packages), reboot into it, ",
                         "then remove this old image (", tag.code("apt autoremove"), "): it keeps its findings until then." ]), class: "state-note kernel-fix")
  end

  # How a resolved package row's findings resolved, in the order RESOLUTIONS lists them: "2 fixed, 1 removed".
  def group_resolutions(group) = group.resolutions.sort_by { |resolution, _| RESOLUTIONS.keys.index(resolution) }.map { |resolution, count| "#{count} #{resolution.tr('_', ' ')}" }.join(", ")

  # "2 high, 18 medium" for a package row, worst first.
  def finding_severity_breakdown(group) = severity_counts(group.counts.select { |_, count| count.positive? })

  # "45 open, 2 reopened" or "3 resolved" for a package row.
  def group_states(group) = group.states.sort_by { |state, _| VulnerabilityFinding::STATES.index(state) }.map { |state, count| "#{count} #{state}" }.join(", ")

  # "2026-11-03 06:12 UTC → —", "... → 2026-11-05 18:30 UTC", or with a resolution and a reopening.
  def finding_dates(finding)
    after = case finding.state
    when "resolved" then utc(finding.resolved_at)
    when "reopened" then tag.span("Resolved #{utc(finding.resolved_at)}, reopened #{utc(finding.reopened_at)}", class: "muted")
    else tag.span("—", class: "muted")
    end
    safe_join([ utc(finding.first_seen_at), " → ", after ])
  end

  # When the finding was first seen, last resolved, and last reopened, oldest first. A finding keeps only its latest
  # resolution and reopening, so earlier rounds are not listed.
  def finding_history(finding)
    events = [ [ finding.first_seen_at, "first seen" ] ]
    events << [ finding.resolved_at, finding.resolution ? "resolved: #{RESOLUTIONS.fetch(finding.resolution).downcase_first}" : "resolved" ] if finding.resolved_at
    events << [ finding.reopened_at, "reopened" ] if finding.reopened_at
    tag.ul(safe_join(events.sort_by(&:first).map { |at, what| tag.li("#{utc(at)} #{what}") }), class: "change-list")
  end

  # The step after a not-evaluated reason, as text or a link.
  def not_evaluated_next_step(host, reason)
    case NEXT_STEPS[reason]
    when :request_packages then safe_join([ link_to("Request a package report", packages_host_path(host, anchor: "request")), " or wait for the next scheduled one." ])
    when :failed_jobs then safe_join([ link_to("Check the failed jobs", failed_jobs_path), ": the first refresh may have failed or not run yet." ])
    else NEXT_STEPS.fetch(reason, "")
    end
  end

  # Triage on the tab (VT-HOST-TAB #260, approved mockup host-vulns.html). Every reason, unit name, and address is
  # plain text that Rails escapes: the listener's unit and sockets are agent data (VulnerabilityTriage::Reasons cleans
  # and cuts them too).
  # Said where a stored rule no longer matches the data as it reads now (review of #281, B1).
  RETRIAGE_PENDING = "Re-triage pending: the data changed since this finding was triaged.".freeze
  # Why rule N5 cannot escalate this host's findings now (HostFacts.listener_coverage, #268's data), said in the Needs
  # attention section so the absence of evidence is never read as "nothing listens". Each ends with the same reassurance:
  # nothing is made less urgent for lack of it (owner decision 2026-11-21).
  LISTENER_NOTES = {
    unread: "Listening services are not read yet, so rule N5 (a package a listening process loads stays here) applies to no finding.",
    not_reported: "This host's agent doesn't report listening data yet (it predates that report, or its last package report carried none), so rule N5 cannot apply here.",
    scan_off: "The library scan is off on this host, so which packages listening processes load is not known, and rule N5 cannot apply here. It is enabled on the VM itself (library_scan = true in the agent's config).",
    scan_failed: "This host's last library scan failed, so which packages listening processes load is not known, and rule N5 cannot apply here until a scan succeeds.",
    kernel_too_old: "This host's kernel can't tell which processes listen: Linux 5.14 or later is needed. So rule N5 cannot apply here.",
    expired: "This host's last library scan is more than 24 hours old, so its listener evidence is no longer used; rule N5 applies again after the next scan."
  }.freeze
  LISTENER_NOTE_TAIL = "Nothing is made less urgent for lack of it: medium or worse findings reachable over the network without a login stay here by rule N4.".freeze

  # The note for a coverage, or nil when the evidence is current (:known).
  def listeners_note(coverage) = (text = LISTENER_NOTES[coverage]) && "#{text} #{LISTENER_NOTE_TAIL}"

  # Source packages named in Work remaining; the rest are counted.
  UPGRADES_LISTED = 8
  BUCKET_CLASSES = { "fix" => "fix", "attention" => "attn", "low_risk" => "low", "ignorable" => "ign" }.freeze
  BUCKET_IDS = { "fix" => "fix", "attention" => "attn", "low_risk" => "low", "ignorable" => "ign", "untriaged" => "untriaged" }.freeze
  # What the Ignorable rules leave to do (mockup: "What you can do").
  IGNORABLE_NEXT = {
    "I1" => "Reboot into a newer image (see Work remaining). Removing an older one is a tidy-up: it changes no exposure.",
    "I5" => "Nothing. It moves out of here if CISA lists it or EPSS rises."
  }.freeze

  def bucket_name(bucket) = VulnerabilityTriage::BUCKET_NAMES.fetch(bucket)

  # The bucket's word with its shape (never colour alone).
  def bucket_tag(bucket) = tag.span(bucket_name(bucket), class: [ "bk", BUCKET_CLASSES.fetch(bucket) ])

  # The sentence for a finding's rule, with the rule id. It is built from the finding's inputs as they read now
  # (Explain) only while they still give the stored rule. When they no longer do (an input changed and the host's
  # re-triage has not run yet: for N5, listener evidence that expired before TriageListenerExpiryJob reached the
  # host), it reads "When triaged: <the rule's summary> Re-triage pending: ...", in the past, so it never states the
  # old rule's evidence as today's fact (reviews of #281, B1 and N5). On a host that is not evaluated now, whose inputs
  # cannot be read, the rule's summary with its KEV and EPSS qualifiers (VT-M1).
  def triage_reason(finding, sections, signals)
    rule = VulnerabilityTriage.rule_for(finding.bucket_rule)
    return tag.span("Not triaged yet.", class: "reason") unless rule

    inputs = sections.inputs[finding.id]
    kev, epss = signal_statuses(signals)
    text = if rule == "O1" && inputs && VulnerabilityTriage.classify(inputs).rule == rule && (decision = sections.decisions&.in_force(finding.advisory_id))
      control_reason(decision, inputs)
    elsif inputs && VulnerabilityTriage.classify(inputs).rule == rule
      # "No EPSS score yet" only once EPSS data exists; before, the "none has been imported" qualifier says it.
      details = { kev_dates: sections.kev_dates, epss_scores: (sections.epss_scores unless epss.nil? || epss.never?) }.compact
      VulnerabilityTriage::Reasons.sentence(rule, inputs, kev:, epss:, details:)
    elsif inputs
      "When triaged: #{VulnerabilityTriage::Reasons::SUMMARIES.fetch(rule)} #{RETRIAGE_PENDING}"
    else
      [ VulnerabilityTriage::Reasons::SUMMARIES.fetch(rule), *rule_qualifiers(rule, signals) ].join(" ")
    end
    reason = tag.span(safe_join([ text, tag.span(rule, class: "rule-id") ]), class: [ "reason", BUCKET_CLASSES.fetch(VulnerabilityTriage::RULES.fetch(rule)) ])
    if rule == "O1" && decision
      safe_join([ tag.span("Control in place", class: "override-tag"), reason, " ", link_to("Change or end", vulnerability_decision_host_path(finding.host_id, decision)) ])
    elsif VulnerabilityTriage::RULES.fetch(rule) == "low_risk" && (other = sections.decisions&.for(finding.advisory_id))
      safe_join([ reason, decision_note(finding.host_id, other, sections.decisions) ].compact)
    else
      reason
    end
  end

  # A decision on a Low risk finding that is not O1 (an acceptance, or a control no longer in force), on its nested
  # row: its tag and its link (review of #299, S3). nil when it ended for good (fixed, resolved, by an operator).
  def decision_note(host_id, decision, decisions)
    link = ->(text) { link_to(text, vulnerability_decision_host_path(host_id, decision)) }
    tag_for = if decision.in_force?(decisions.today) then [ decision.kind_name, ("accepted" if decision.accepted?), "Until #{decision.expires_on.iso8601}." ]
    elsif decision.active? then [ "Decision expired", "suspended", "Its last day was #{decision.expires_on.iso8601}." ]
    elsif decision.suspended? then [ "Decision suspended", "suspended", "The evidence got worse (#{FindingDecisions.changes_words(decision.ended_evidence.to_h)})." ]
    end
    return nil unless tag_for

    name, css, note = tag_for
    tag.span(safe_join([ tag.span(name, class: [ "override-tag", css ].compact), " ", note, " ", link.("Change or end") ]), class: "state-note decision-note")
  end

  # Rule O1's reason (VT-OVERRIDES #261, mockup override.html): who recorded the control and when, until when, its text
  # (operator text, escaped where it is rendered), and the bucket the rules give without it.
  def control_reason(decision, inputs)
    without = VulnerabilityTriage.classify(inputs.with(control: false)).rule
    "#{decision.created_by.display_name} recorded on #{decision.created_at.utc.to_date.iso8601}, until #{decision.expires_on.iso8601}: " \
      "\u201C#{decision.reason}\u201D Without it: #{bucket_name(VulnerabilityTriage::RULES.fetch(without))} (#{without})."
  end

  # The Needs attention row's decision cell (VT-OVERRIDES #261, VT-D04; mockups host-vulns.html and override.html): the
  # decision in force (an accepted risk stays here, marked, and is not due; a control here means its re-triage has not
  # run yet), one past its last day that the hourly job has not ended, a suspended one with what got worse, or the link
  # to record one. Operator text is escaped.
  def decision_cell(host, advisory, decisions)
    decision = decisions.for(advisory.id)
    record = safe_join([ link_to("Record a control\u2026", new_vulnerability_decision_host_path(host, advisory_id: advisory.id, kind: "control")),
                         link_to("Accept the risk\u2026", new_vulnerability_decision_host_path(host, advisory_id: advisory.id, kind: "accepted")) ], tag.br)
    return record if decision.nil?

    change = link_to("Change or end", vulnerability_decision_host_path(host, decision))
    by = "#{decision.kind == 'control' ? 'Recorded' : 'Accepted'} by #{decision.created_by.display_name} on #{decision.created_at.utc.to_date.iso8601}: \u201C#{decision.reason}\u201D"
    if decision.in_force?(decisions.today)
      soon = decisions.ending_soon?(decision) ? " It ends within #{FindingDecisions::EXPIRING_WITHIN} days, so it is listed as due." : ""
      note = decision.accepted? ? "Until #{decision.expires_on.iso8601}. Still counted here, with its points; not due.#{soon}" : "Until #{decision.expires_on.iso8601}. #{RETRIAGE_PENDING}#{soon}"
      safe_join([ tag.span(decision.kind_name, class: [ "override-tag", ("accepted" if decision.accepted?) ]), tag.span(note, class: "state-note"), tag.span(by, class: "state-note"), change ])
    elsif decision.active?
      safe_join([ tag.span("Decision expired", class: "override-tag suspended"), tag.span("Its last day was #{decision.expires_on.iso8601}; it ends within the hour and the finding is due a new decision.", class: "state-note") ])
    elsif decision.suspended?
      what = FindingDecisions.changes_words(decision.ended_evidence.to_h)
      text = "#{decision.kind_name} by #{decision.created_by.display_name} on #{decision.created_at.utc.to_date.iso8601} (\u201C#{decision.reason}\u201D), " \
             "but on #{decision.ended_at.utc.to_date.iso8601} the evidence got worse (#{what}). It no longer applies; the finding is due a new decision."
      safe_join([ tag.span("Decision suspended", class: "override-tag suspended"), tag.span(text, class: "state-note"), link_to("Record a new decision\u2026", new_vulnerability_decision_host_path(host, advisory_id: advisory.id)) ])
    else
      safe_join([ record, tag.span("The last decision #{DECISION_ENDINGS.fetch(decision.ended_why)} on #{decision.ended_at.utc.to_date.iso8601}.", class: "state-note") ])
    end
  end

  # One host's evidence on the decision form (N8): its bucket and rule, listening, and firewall.
  def decision_candidate_evidence(candidate)
    firewall = { true => "firewall enabled", false => "firewall disabled" }.fetch(candidate.firewall, "firewall not reported")
    safe_join([
      (safe_join([ bucket_tag(candidate.bucket), " (", tag.span(candidate.rule, class: "mono"), ")" ]) if candidate.bucket),
      (tag.span(candidate.listening == "network" ? "Listening: network" : "Listening: loopback only", class: "sig use") unless candidate.listening == "none"),
      (candidate.listening == "none" ? "no listener reported" : nil), firewall
    ].compact, " \u00B7 ")
  end

  DECISION_ENDINGS = { "operator" => "was ended by an operator", "expired" => "expired", "fixed" => "ended when a fix appeared", "resolved" => "ended when its findings resolved" }.freeze

  # A rule's row in the Low risk and Ignorable tables: its summary and the KEV and EPSS qualifiers that rule takes
  # (they depend on the rule alone; review of #281, S2).
  def rule_summary(rule, signals)
    text = [ VulnerabilityTriage::Reasons::SUMMARIES.fetch(rule), *rule_qualifiers(rule, signals) ].join(" ")
    tag.span(safe_join([ text, tag.span(rule, class: "rule-id") ]), class: [ "reason", BUCKET_CLASSES.fetch(VulnerabilityTriage::RULES.fetch(rule)) ])
  end

  # "Not checked against CISA's KEV list: none has been imported." and the like, for a rule KEV or EPSS could change.
  def rule_qualifiers(rule, signals)
    kev, epss = signal_statuses(signals)
    VulnerabilityTriage::Reasons.qualifiers(rule, nil, kev, epss, {})
  end

  def signal_statuses(signals) = %w[kev epss].map { |name| signals.find { |status| status.signal == name } }

  # The signals beside a Needs attention advisory: known exploited, its EPSS score, its attack vector in words, and,
  # when VT-APPLICABILITY reports one, the listener that loads the package (N5's evidence).
  def advisory_signals(group, sections)
    advisory = group.advisory
    inputs = group.findings.filter_map { |finding| sections.inputs[finding.id] }
    cves = inputs.flat_map(&:cve_ids).uniq
    epss = sections.epss_scores.values_at(*cves).compact.max
    words = VulnerabilityTriage::Reasons.vector_words(advisory.cvss_av, advisory.cvss_pr, advisory.cvss_ui)
    listener = inputs.filter_map(&:listener).max_by { |l| l.network ? 1 : 0 }
    safe_join([
      (tag.span("Known exploited", class: "sig kev") if group.kev?),
      (tag.span("EPSS #{(epss.to_d * 100).round}%", class: "sig epss") if epss),
      (tag.span(safe_join([ words.upcase_first, tag.span(VulnerabilityTriage::Reasons.vector_text(advisory.cvss_av, advisory.cvss_pr, advisory.cvss_ui), class: "vecraw") ]), class: "sig vec") if words),
      (tag.span(listener.network ? "Listening: network" : "Listening: loopback only", class: "sig use") if listener)
    ].compact)
  end

  # A Fix available package row's action: the highest fix among its findings (F1's version, or F2's from Debian's
  # tracker when its inputs can be read).
  def upgrade_action(group, sections)
    # Every finding of the row, not only those drawn: the Fix available rows' inputs are all loaded (HostTriageSections).
    versions = group.findings.filter_map { |f| (inputs = sections.inputs[f.id]) ? VulnerabilityTriage.fix_for(inputs) : f.fixed_version }.uniq
    scheme = group.findings.filter_map { |f| sections.inputs[f.id]&.scheme }.first
    best = scheme ? versions.max { |a, b| VulnerabilityTriage.compare(a, b, scheme) || 0 } : versions.max
    best ? safe_join([ "Upgrade to ", tag.span(best, class: "mono") ]) : "Upgrade"
  end

  # A kernel row's action: reboot into the installed newer image (K1), or install the new kernel package, then reboot
  # (K2). The update task does neither (DEC-16). The image to reboot into is named only while today's data still gives
  # K1; once it no longer does (the host rebooted, or the newer image was purged, and its re-triage has not run), the
  # row says "the newer kernel" with the pending note, never a kernel that is running or gone (re-check of #281, S1).
  def kernel_action(group, sections)
    shown = HostTriageSections.shown(group)
    rules = shown.map { |f| VulnerabilityTriage.rule_for(f.bucket_rule) }
    stale = shown.any? { |f| (inputs = sections.inputs[f.id]) && VulnerabilityTriage.classify(inputs).rule != VulnerabilityTriage.rule_for(f.bucket_rule) }
    inputs = shown.filter_map { |f| sections.inputs[f.id] }.first
    target = kernel_target(inputs) if !stale && inputs && VulnerabilityTriage.classify(inputs).rule == "K1"
    reboot = target ? safe_join([ tag.strong("Reboot"), " into ", tag.span(target, class: "mono"), " (installed)" ]) : safe_join([ tag.strong("Reboot"), " into the newer kernel" ])
    install = safe_join([ tag.strong("Install the new kernel package"), " (", tag.code("apt full-upgrade"), "), then reboot" ])
    parts = [ (reboot if rules.include?("K1")), (install if rules.include?("K2")) ].compact
    parts << tag.span(RETRIAGE_PENDING, class: "state-note") if stale
    safe_join(parts, tag.br)
  end

  # The image K1 reboots into: the newest installed image of the running image's flavour, or nil.
  def kernel_target(inputs)
    kernel = inputs.kernel
    flavour = inputs.image&.flavour
    return nil unless kernel && flavour

    # The newest image of the flavour: under K1 an image at or above the fix is installed, so it is never the running
    # one (which has the finding).
    kernel.images.select { |image| image.flavour == flavour }.max { |a, b| VulnerabilityTriage.compare(a.version, b.version, inputs.scheme) || 0 }&.release
  end

  # The proportion bar: an SVG whose geometry is in attributes (no inline style, the app's CSP), with its text
  # equivalent as its label. counts: { bucket => findings }, open: their sum.
  def bucket_bar(counts, open)
    x = 0
    rects = VulnerabilityTriage::BUCKETS.keys.filter_map do |bucket|
      width = open.zero? ? 0 : (counts[bucket] * 1000.0 / open).round
      next if width.zero?

      tag.rect(class: "f-#{BUCKET_CLASSES.fetch(bucket)}", x:, y: 0, width:, height: 12).tap { x += width }
    end
    tag.svg(safe_join(rects), class: "propbar", viewBox: "0 0 1000 12", preserveAspectRatio: "none", role: "img", "aria-label": "Share of the #{number_with_delimiter(open)} open findings: #{bucket_shares(counts, open)}")
  end

  # "fix available 2% · needs attention under 1% · low risk 33% · ignorable 65%".
  def bucket_shares(counts, open)
    VulnerabilityTriage::BUCKETS.keys.map do |bucket|
      n = counts[bucket]
      share = if n.zero? then "none"
      elsif n * 100 < open then "under 1%"
      else "#{(n * 100.0 / open).round}%"
      end
      "#{bucket_name(bucket).downcase} #{share}"
    end.join(" · ")
  end

  # Why progress is not shown (VT-M5 rule 2: no meter on a host that is not evaluated, or whose package report is older
  # than PROGRESS_REPORT_MAX_AGE), or nil.
  PROGRESS_REPORT_MAX_AGE = 3.days
  def progress_withheld(summary, now: Time.current)
    return "this host is not evaluated now, so its work cannot be counted." unless summary.vulnerabilities_evaluated?

    received = summary.received["packages"]
    return nil if received && received >= now - PROGRESS_REPORT_MAX_AGE

    "its last package report is older than #{human_duration(PROGRESS_REPORT_MAX_AGE)}, so work done since may not show yet."
  end

  # "7 upgrades, a new kernel installed, a reboot".
  def work_done_words(by_kind)
    words = { "upgrade" => [ "an upgrade", "upgrades" ], "kernel_installed" => [ "a new kernel installed", "new kernels installed" ], "reboot" => [ "a reboot", "reboots" ] }
    words.filter_map { |kind, (one, many)| (n = by_kind[kind].to_i).positive? && (n == 1 ? one : "#{n} #{many}") }.to_sentence
  end

  # --- The package page's filters and buckets (#283) ---

  PACKAGE_SECTION_WORDS = {
    "kernel" => "Fix available, the kernel's steps (K1, K2)", "fix" => "Fix available, package upgrades (F1, F2)", "untriaged" => "not triaged yet"
  }.freeze
  PACKAGE_STATE_WORDS = { "open" => "open and reopened", "resolved" => "resolved" }.freeze
  PACKAGE_SIGNAL_WORDS = { "kev" => "known exploited (KEV)", "epss" => "EPSS high", "network" => "network, no login, no user action" }.freeze

  # The tab's "N more" link under a package row: the package page with the tab's filters and the row's section and
  # architecture, starting after the last finding the row drew, so it opens on exactly the findings it counts. section:
  # one of HostTriageSections::PACKAGE_SECTIONS; rule: the rule shown, for "rule".
  def package_more_path(host, group, link_params:, section:, rule: nil)
    params = { package: group.package, arch: group.architecture, state: "open", section:, rule: (rule if section == "rule"),
               **link_params.slice(:severity, :signal, :q, :debian, :fix), after: HostPackageFindings.cursor_of(HostTriageSections.shown(group).last), from: "tab" }
    package_vulnerabilities_host_path(host, params.compact)
  end

  # "open and reopened, severity high, rule L2 (Low risk)": the package page's filters in words, the text search
  # escaped as any text is.
  def package_filter_words(filters)
    words = []
    words << PACKAGE_STATE_WORDS.fetch(filters[:state]) if filters[:state]
    words << (filters[:section] == "rule" ? "rule #{filters[:rule]} (#{bucket_name(VulnerabilityTriage::RULES.fetch(filters[:rule]))})" : PACKAGE_SECTION_WORDS.fetch(filters[:section])) if filters[:section]
    words << "architecture #{filters[:arch]}" if filters[:arch]
    words << "severity #{filters[:severity]}" if filters[:severity]
    words << "signal: #{PACKAGE_SIGNAL_WORDS.fetch(filters[:signal])}" if filters[:signal]
    words << "Debian: no security update planned" if filters[:debian]
    words << "the advisory data names a fix" if filters[:fix]
    words << "matching \u201c#{filters[:q]}\u201d" if filters[:q]
    words.join(", ")
  end

  # A finding's bucket and reason on the package page, as on the tab; a resolved finding is in no bucket. triage_reason
  # draws O1's control and a Low risk finding's decision as on the tab; a Needs attention finding's decision, which the
  # tab draws in its Decision column, is tagged here the same way (VT-OVERRIDES #261).
  def package_finding_bucket(finding, details, signals)
    return tag.span("Resolved: in no bucket", class: "muted") if finding.state == "resolved"

    bucket = VulnerabilityTriage.bucket_for(finding.bucket)
    decision = bucket == "attention" && details.decisions&.for(finding.advisory_id)
    safe_join([ (bucket_tag(bucket) if bucket), " ", triage_reason(finding, details, signals), (decision_note(finding.host_id, decision, details.decisions) if decision) ].compact)
  end
end
