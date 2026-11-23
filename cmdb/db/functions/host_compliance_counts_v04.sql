CREATE OR REPLACE FUNCTION host_compliance_counts(host_ids bigint[])
RETURNS TABLE (
  host_id bigint,
  cis_passed integer, cis_failed integer, cis_not_readable integer,
  cis_critical integer, cis_high integer, cis_medium integer, cis_low integer,
  vuln_critical integer, vuln_high integer, vuln_medium integer, vuln_low integer, vuln_unknown integer,
  vuln_evaluated boolean,
  vuln_fixable integer, vuln_fix_packages integer, vuln_fix_severities smallint,
  vuln_fix integer, vuln_attention integer, vuln_low_risk integer, vuln_ignorable integer, vuln_kev_open integer,
  exposure_tier smallint, exposure_points integer, vuln_kev_advisories integer, vuln_fix_critical integer,
  vuln_attention_undecided integer, work_upgrades integer, work_kernel_install boolean, work_reboot boolean, work_items integer
)
LANGUAGE sql
STABLE
AS $$
  -- A host's compliance counts, computed from the rows the host pages show (P2-D05, #193): CIS results with the
  -- severity of the rule version that produced them (the current version when a result names none), open and
  -- reopened findings with their advisory's severity, and whether its last matching run evaluated it.
  --
  -- v02 (VT-FIXABLE, #256): of the open and reopened findings, how many have a fix (the finding's stored flag), how
  -- many distinct binary packages and architectures they are on, and which severities have one (a bit per severity,
  -- critical 1, high 2, medium 4, low 8, unknown 16, for the Compliance page's "of this severity, with a fix"). A
  -- host its last matching run did not evaluate counts none of them (#252 question 6), though its kept findings are
  -- still open.
  --
  -- v03 (VT-BUCKETS, #259): the open and reopened findings per triage bucket (1 Fix available, 2 Needs attention,
  -- 3 Low risk, 4 Ignorable), and those with the KEV flag. Counted for every host, evaluated or not, so the four
  -- always add up to the open count: a host that is not evaluated keeps its findings and their buckets as they were.
  --
  -- v04 (VT-SCORES, #262; the epic's VT-M3 and VT-M4): the host's exposure and work, scored only when its last matching
  -- run evaluated it and every open finding has a bucket (else NULL: never a 0 or a lower tier that stands for data
  -- not there yet). Each open advisory counts once, in the worst bucket of its findings (Needs attention, Fix
  -- available, Low risk by a control, Low risk, Ignorable), with the stored KEV flag of any of them and the widest
  -- listener among them outside Ignorable (vulnerability_findings.listener: 2 network, 1 loopback):
  -- - exposure_points: vulnerability_exposure_points over those advisories;
  -- - exposure_tier: 4 Known exploited (a KEV advisory in Needs attention, Fix available, or under a control), else 3
  --   Exposed, no fix (a critical or high in Needs attention), else 2 Fixes waiting (a critical or high in Fix
  --   available), else 1 Low (any points), else 0 Minimal;
  -- - vuln_kev_advisories: KEV advisories outside Ignorable; vuln_fix_critical: critical advisories with a finding in
  --   Fix available (the run badge's "fixable critical"); vuln_attention_undecided: advisories with a finding in Needs
  --   attention and no decision (VT-OVERRIDES records decisions; until then, every one);
  -- - work: one upgrade per source package with F1 or F2 findings, the new kernel package to install (K2), and a reboot
  --   (K1, or the agent's reboot flag, host_applicability.reboot_required); work_items is their sum.
  -- The KEV, EPSS, and tracker sources' freshness is not here: it is a read-time qualifier, so a feed going stale
  -- rewrites no summary and never lowers a score.
  SELECT h.id,
         cis.passed, cis.failed, cis.not_readable, cis.critical, cis.high, cis.medium, cis.low,
         vulns.critical, vulns.high, vulns.medium, vulns.low, vulns.unknown,
         COALESCE(hve.state = 'evaluated', false),
         CASE WHEN hve.state = 'evaluated' THEN vulns.fixable ELSE 0 END,
         CASE WHEN hve.state = 'evaluated' THEN vulns.fix_packages ELSE 0 END,
         CASE WHEN hve.state = 'evaluated' THEN vulns.fix_severities ELSE 0::smallint END,
         vulns.bucket_fix, vulns.bucket_attention, vulns.bucket_low_risk, vulns.bucket_ignorable, vulns.kev_open,
         CASE WHEN scored.yes THEN
           (CASE WHEN adv.known_exploited THEN 4 WHEN adv.exposed THEN 3 WHEN adv.fixes_waiting THEN 2 WHEN adv.points > 0 THEN 1 ELSE 0 END)::smallint
         END,
         CASE WHEN scored.yes THEN adv.points END,
         adv.kev_advisories, adv.fix_critical, adv.undecided,
         CASE WHEN scored.yes THEN vulns.upgrades END,
         scored.yes AND vulns.kernel_install,
         scored.yes AND (vulns.reboot OR COALESCE(ha.reboot_required, false)),
         CASE WHEN scored.yes THEN vulns.upgrades + vulns.kernel_install::integer + (vulns.reboot OR COALESCE(ha.reboot_required, false))::integer END
    FROM (SELECT DISTINCT unnest(host_ids) AS id) h
    LEFT JOIN LATERAL (
      SELECT count(*) FILTER (WHERE r.result = 'pass')::integer AS passed,
             count(*) FILTER (WHERE r.result = 'fail')::integer AS failed,
             count(*) FILTER (WHERE r.result = 'not_readable')::integer AS not_readable,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'critical')::integer AS critical,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'high')::integer AS high,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'medium')::integer AS medium,
             count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'low')::integer AS low
        FROM cis_results r
        JOIN cis_rules ru ON ru.id = r.cis_rule_id
        LEFT JOIN cis_rule_versions rv ON rv.id = r.cis_rule_version_id
        LEFT JOIN cis_rule_versions cv ON cv.id = ru.current_version_id
       WHERE r.host_id = h.id
    ) cis ON true
    LEFT JOIN LATERAL (
      SELECT count(*) FILTER (WHERE a.severity = 'critical')::integer AS critical,
             count(*) FILTER (WHERE a.severity = 'high')::integer AS high,
             count(*) FILTER (WHERE a.severity = 'medium')::integer AS medium,
             count(*) FILTER (WHERE a.severity = 'low')::integer AS low,
             count(*) FILTER (WHERE a.severity = 'unknown')::integer AS unknown,
             count(*) FILTER (WHERE f.last_fixed_version IS NOT NULL)::integer AS fixable,
             count(DISTINCT (f.package, f.architecture)) FILTER (WHERE f.last_fixed_version IS NOT NULL)::integer AS fix_packages,
             COALESCE(bit_or(CASE a.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 4 WHEN 'low' THEN 8 ELSE 16 END)
                             FILTER (WHERE f.last_fixed_version IS NOT NULL), 0)::smallint AS fix_severities,
             count(*) FILTER (WHERE f.bucket = 1)::integer AS bucket_fix,
             count(*) FILTER (WHERE f.bucket = 2)::integer AS bucket_attention,
             count(*) FILTER (WHERE f.bucket = 3)::integer AS bucket_low_risk,
             count(*) FILTER (WHERE f.bucket = 4)::integer AS bucket_ignorable,
             count(*) FILTER (WHERE f.kev)::integer AS kev_open,
             count(*) FILTER (WHERE f.bucket IS NULL)::integer AS untriaged,
             -- rules F1 and F2 (5, 6) are package upgrades, K2 (4) a new kernel package, K1 (3) a reboot
             count(DISTINCT COALESCE(f.last_source, f.package)) FILTER (WHERE f.bucket_rule IN (5, 6))::integer AS upgrades,
             COALESCE(bool_or(f.bucket_rule = 4), false) AS kernel_install,
             COALESCE(bool_or(f.bucket_rule = 3), false) AS reboot
        FROM vulnerability_findings f
        JOIN advisories a ON a.id = f.advisory_id
       WHERE f.host_id = h.id AND f.state IN ('open', 'reopened')
    ) vulns ON true
    LEFT JOIN host_vulnerability_evaluations hve ON hve.host_id = h.id
    LEFT JOIN host_applicability ha ON ha.host_id = h.id
    CROSS JOIN LATERAL (SELECT COALESCE(hve.state = 'evaluated', false) AND vulns.untriaged = 0 AS yes) scored
    LEFT JOIN LATERAL (
      SELECT COALESCE(sum(vulnerability_exposure_points(x.worst, x.severity, x.kev, x.listener)), 0)::integer AS points,
             COALESCE(bool_or(x.kev AND x.worst >= 3), false) AS known_exploited,
             COALESCE(bool_or(x.severity IN ('critical', 'high') AND x.worst = 5), false) AS exposed,
             COALESCE(bool_or(x.severity IN ('critical', 'high') AND x.worst = 4), false) AS fixes_waiting,
             count(*) FILTER (WHERE x.kev AND x.worst >= 2)::integer AS kev_advisories,
             count(*) FILTER (WHERE x.severity = 'critical' AND x.in_fix)::integer AS fix_critical,
             count(*) FILTER (WHERE x.in_attention)::integer AS undecided
        FROM (
          -- One row per open advisory, in the worst bucket of its findings: 5 Needs attention, 4 Fix available, 3 Low
          -- risk by a control (rule O1, 9), 2 Low risk, 1 Ignorable.
          SELECT a.severity::text AS severity,
                 max(CASE WHEN f.bucket = 2 THEN 5 WHEN f.bucket = 1 THEN 4 WHEN f.bucket_rule = 9 THEN 3 WHEN f.bucket = 3 THEN 2 ELSE 1 END)::smallint AS worst,
                 bool_or(f.kev) AS kev,
                 max(f.listener) FILTER (WHERE f.bucket <> 4) AS listener,
                 bool_or(f.bucket = 1) AS in_fix,
                 bool_or(f.bucket = 2) AS in_attention
            FROM vulnerability_findings f
            JOIN advisories a ON a.id = f.advisory_id
           WHERE f.host_id = h.id AND f.state IN ('open', 'reopened') AND f.bucket IS NOT NULL
           GROUP BY f.advisory_id, a.severity
        ) x
    ) adv ON true;
$$;
