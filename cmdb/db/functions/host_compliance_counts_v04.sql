CREATE OR REPLACE FUNCTION host_compliance_counts(host_ids bigint[])
RETURNS TABLE (
  host_id bigint,
  cis_passed integer, cis_failed integer, cis_not_readable integer,
  cis_critical integer, cis_high integer, cis_medium integer, cis_low integer,
  vuln_critical integer, vuln_high integer, vuln_medium integer, vuln_low integer, vuln_unknown integer,
  vuln_evaluated boolean,
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
  -- v04 (VT-SCORES, #262; the epic's VT-M3 and VT-M4): v02's fix counts are gone (the buckets replace them on every
  -- page, #281 item 1; the findings keep their fix flag), and the host's exposure and work are counted, scored only when its last matching
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
  --   attention and no decision in force (#298: an accepted risk or a control whose ended_at is NULL), as the host
  --   tab's decisions due count them, less the decisions ending soon, lapsed, or suspended, which depend on the date
  --   and stay a read-time part (HostDecisions);
  -- - work: one upgrade per source package with F1 or F2 findings, the new kernel package to install (K2), and a reboot
  --   (K1, or the agent's reboot flag, host_applicability.reboot_required); work_items is their sum.
  -- The KEV, EPSS, and tracker sources' freshness is not here: it is a read-time qualifier, so a feed going stale
  -- rewrites no summary and never lowers a score.
  SELECT h.id,
         cis.passed, cis.failed, cis.not_readable, cis.critical, cis.high, cis.medium, cis.low,
         vulns.critical, vulns.high, vulns.medium, vulns.low, vulns.unknown,
         COALESCE(hve.state = 'evaluated', false),
         vulns.bucket_fix, vulns.bucket_attention, vulns.bucket_low_risk, vulns.bucket_ignorable, vulns.kev_open,
         CASE WHEN scored.yes THEN
           (CASE WHEN vulns.known_exploited THEN 4 WHEN vulns.exposed THEN 3 WHEN vulns.fixes_waiting THEN 2 WHEN vulns.points > 0 THEN 1 ELSE 0 END)::smallint
         END,
         CASE WHEN scored.yes THEN vulns.points END,
         vulns.kev_advisories, vulns.fix_critical, vulns.undecided,
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
    -- The host's open findings are read once (one index scan and one join to advisories), grouped two ways in that one
    -- pass (v04): by advisory, for the severity and bucket counts and the exposure, and by source package, for the
    -- upgrades. Each finding is in exactly one group of each set.
    LEFT JOIN LATERAL (
      SELECT COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'critical'), 0)::integer AS critical,
             COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'high'), 0)::integer AS high,
             COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'medium'), 0)::integer AS medium,
             COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'low'), 0)::integer AS low,
             COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'unknown'), 0)::integer AS unknown,
             COALESCE(sum(g.in_fix) FILTER (WHERE g.set = 0), 0)::integer AS bucket_fix,
             COALESCE(sum(g.in_attention) FILTER (WHERE g.set = 0), 0)::integer AS bucket_attention,
             COALESCE(sum(g.in_low_risk) FILTER (WHERE g.set = 0), 0)::integer AS bucket_low_risk,
             COALESCE(sum(g.in_ignorable) FILTER (WHERE g.set = 0), 0)::integer AS bucket_ignorable,
             COALESCE(sum(g.kev_findings) FILTER (WHERE g.set = 0), 0)::integer AS kev_open,
             COALESCE(sum(g.untriaged) FILTER (WHERE g.set = 0), 0)::integer AS untriaged,
             count(*) FILTER (WHERE g.set = 1 AND g.upgrade)::integer AS upgrades,
             COALESCE(bool_or(g.kernel_install) FILTER (WHERE g.set = 0), false) AS kernel_install,
             COALESCE(bool_or(g.reboot) FILTER (WHERE g.set = 0), false) AS reboot,
             COALESCE(sum(vulnerability_exposure_points(g.worst, g.severity, g.kev, g.listener)) FILTER (WHERE g.set = 0), 0)::integer AS points,
             COALESCE(bool_or(g.kev AND g.worst >= 3) FILTER (WHERE g.set = 0), false) AS known_exploited,
             COALESCE(bool_or(g.severity IN ('critical', 'high') AND g.worst = 5) FILTER (WHERE g.set = 0), false) AS exposed,
             COALESCE(bool_or(g.severity IN ('critical', 'high') AND g.worst = 4) FILTER (WHERE g.set = 0), false) AS fixes_waiting,
             count(*) FILTER (WHERE g.set = 0 AND g.kev AND g.worst >= 2)::integer AS kev_advisories,
             count(*) FILTER (WHERE g.set = 0 AND g.severity = 'critical' AND g.in_fix > 0)::integer AS fix_critical,
             count(*) FILTER (WHERE g.set = 0 AND g.in_attention > 0 AND NOT (g.advisory_id = ANY (dec.ids)))::integer AS undecided
        FROM (
          -- Set 0, one row per open advisory, in the worst bucket of its triaged findings (5 Needs attention, 4 Fix
          -- available, 3 Low risk by a control (rule O1, 9), 2 Low risk, 1 Ignorable), with the KEV flag of any of them
          -- and the widest listener outside Ignorable; set 1, one per source package.
          SELECT CASE WHEN GROUPING(f.advisory_id) = 0 THEN 0 ELSE 1 END AS set,
                 f.advisory_id,
                 a.severity::text AS severity,
                 count(*) AS n,
                 count(*) FILTER (WHERE f.bucket = 1) AS in_fix,
                 count(*) FILTER (WHERE f.bucket = 2) AS in_attention,
                 count(*) FILTER (WHERE f.bucket = 3) AS in_low_risk,
                 count(*) FILTER (WHERE f.bucket = 4) AS in_ignorable,
                 count(*) FILTER (WHERE f.kev) AS kev_findings,
                 count(*) FILTER (WHERE f.bucket IS NULL) AS untriaged,
                 -- rules F1 and F2 (5, 6) are package upgrades, K2 (4) a new kernel package, K1 (3) a reboot
                 bool_or(f.bucket_rule IN (5, 6)) AS upgrade,
                 bool_or(f.bucket_rule = 4) AS kernel_install,
                 bool_or(f.bucket_rule = 3) AS reboot,
                 max(CASE WHEN f.bucket = 2 THEN 5 WHEN f.bucket = 1 THEN 4 WHEN f.bucket_rule = 9 THEN 3 WHEN f.bucket = 3 THEN 2 WHEN f.bucket = 4 THEN 1 END)::smallint AS worst,
                 COALESCE(bool_or(f.kev), false) AS kev,
                 max(f.listener) FILTER (WHERE f.bucket <> 4) AS listener
            FROM vulnerability_findings f
            JOIN advisories a ON a.id = f.advisory_id
           WHERE f.host_id = h.id AND f.state IN ('open', 'reopened')
           GROUP BY GROUPING SETS ((f.advisory_id, a.severity), (COALESCE(f.last_source, f.package)))
        ) g
        -- The advisories with a decision in force on the host (VT-OVERRIDES #261: an accepted risk keeps its finding in
        -- Needs attention, a control moves it to Low risk), read as ended_at IS NULL, one probe of the active index.
        CROSS JOIN (SELECT COALESCE(array_agg(d.advisory_id), '{}'::bigint[]) AS ids
                      FROM finding_decisions d WHERE d.host_id = h.id AND d.ended_at IS NULL) dec
    ) vulns ON true
    LEFT JOIN host_vulnerability_evaluations hve ON hve.host_id = h.id
    LEFT JOIN host_applicability ha ON ha.host_id = h.id
    CROSS JOIN LATERAL (SELECT COALESCE(hve.state = 'evaluated', false) AND vulns.untriaged = 0 AS yes) scored;
$$;
