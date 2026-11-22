CREATE OR REPLACE FUNCTION host_compliance_summaries_refresh(host_ids bigint[])
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Recomputes the hosts' compliance counts (#193). Called from host_compliance_summaries_flush at commit, which has
  -- already locked these rows in one sorted statement, and by the rebuild and the recount queue. v02 (VT-FIXABLE,
  -- #256): also the open findings with a fix, their packages, and their severities. v03 (VT-BUCKETS, #259): also the
  -- open findings per triage bucket and those with the KEV flag.
  IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
    RETURN;
  END IF;

  -- Lock first, in host order, then count in a later statement: under READ COMMITTED that statement takes a new
  -- snapshot, so a transaction that waited here for another one counts what that one committed. Two transactions
  -- changing one host's rows at once therefore leave the counts of both, whichever commits first.
  PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (host_ids) ORDER BY s.host_id FOR UPDATE;

  UPDATE host_compliance_summaries s
     SET cis_passed = c.cis_passed, cis_failed = c.cis_failed, cis_not_readable = c.cis_not_readable,
         cis_critical = c.cis_critical, cis_high = c.cis_high, cis_medium = c.cis_medium, cis_low = c.cis_low,
         vuln_critical = c.vuln_critical, vuln_high = c.vuln_high, vuln_medium = c.vuln_medium, vuln_low = c.vuln_low,
         vuln_unknown = c.vuln_unknown, vuln_evaluated = c.vuln_evaluated,
         vuln_fixable = c.vuln_fixable, vuln_fix_packages = c.vuln_fix_packages, vuln_fix_severities = c.vuln_fix_severities,
         vuln_fix = c.vuln_fix, vuln_attention = c.vuln_attention, vuln_low_risk = c.vuln_low_risk, vuln_ignorable = c.vuln_ignorable,
         vuln_kev_open = c.vuln_kev_open
    FROM host_compliance_counts(host_ids) c
   WHERE s.host_id = c.host_id
     AND (s.cis_passed, s.cis_failed, s.cis_not_readable, s.cis_critical, s.cis_high, s.cis_medium, s.cis_low,
          s.vuln_critical, s.vuln_high, s.vuln_medium, s.vuln_low, s.vuln_unknown, s.vuln_evaluated,
          s.vuln_fixable, s.vuln_fix_packages, s.vuln_fix_severities,
          s.vuln_fix, s.vuln_attention, s.vuln_low_risk, s.vuln_ignorable, s.vuln_kev_open)
         IS DISTINCT FROM
         (c.cis_passed, c.cis_failed, c.cis_not_readable, c.cis_critical, c.cis_high, c.cis_medium, c.cis_low,
          c.vuln_critical, c.vuln_high, c.vuln_medium, c.vuln_low, c.vuln_unknown, c.vuln_evaluated,
          c.vuln_fixable, c.vuln_fix_packages, c.vuln_fix_severities,
          c.vuln_fix, c.vuln_attention, c.vuln_low_risk, c.vuln_ignorable, c.vuln_kev_open);
END;
$$;
