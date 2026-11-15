CREATE OR REPLACE FUNCTION host_compliance_counts(host_ids bigint[])
RETURNS TABLE (
  host_id bigint,
  cis_passed integer, cis_failed integer, cis_not_readable integer,
  cis_critical integer, cis_high integer, cis_medium integer, cis_low integer,
  vuln_critical integer, vuln_high integer, vuln_medium integer, vuln_low integer, vuln_unknown integer,
  vuln_evaluated boolean
)
LANGUAGE sql
STABLE
AS $$
  -- A host's compliance counts, computed from the rows the host pages show (P2-D05, #193): CIS results with the
  -- severity of the rule version that produced them (the current version when a result names none), open and
  -- reopened findings with their advisory's severity, and whether its last matching run evaluated it.
  SELECT h.id,
         cis.passed, cis.failed, cis.not_readable, cis.critical, cis.high, cis.medium, cis.low,
         vulns.critical, vulns.high, vulns.medium, vulns.low, vulns.unknown,
         COALESCE(hve.state = 'evaluated', false)
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
             count(*) FILTER (WHERE a.severity = 'unknown')::integer AS unknown
        FROM vulnerability_findings f
        JOIN advisories a ON a.id = f.advisory_id
       WHERE f.host_id = h.id AND f.state IN ('open', 'reopened')
    ) vulns ON true
    LEFT JOIN host_vulnerability_evaluations hve ON hve.host_id = h.id;
$$;
