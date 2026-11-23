CREATE OR REPLACE FUNCTION host_compliance_summaries_refresh(host_ids bigint[])
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  grace interval;
BEGIN
  -- Recomputes the hosts' compliance counts (#193). Called from host_compliance_summaries_flush at commit, which has
  -- already locked these rows in one sorted statement, and by the rebuild and the recount queue. v02 (VT-FIXABLE,
  -- #256): also the open findings with a fix, their packages, and their severities. v03 (VT-BUCKETS, #259): also the
  -- open findings per triage bucket and those with the KEV flag. v04 (VT-SCORES, #262): not v02's fix counts, whose
  -- columns are dropped, but the exposure tier and points, the work items, and the run's two times:
  -- - fixable_critical_since: when the host last went from no critical advisory in Fix available to one (NULL while
  --   it has none);
  -- - no_fixable_critical_since: when its current run began, kept while a fixable critical is open. When the last one
  --   goes, the run carries on if it was open for less than the grace, and starts again now otherwise (a run's badge
  --   is read from these with the same grace: VulnerabilityExposure::Run). A host that is not scored (not evaluated
  --   now, or not every open finding triaged) has neither: its run ends, and a new one starts when it is scored again,
  --   so a run never counts days the server could not see (S4 of the review of #305). A gap in package reports ends a
  --   run too (host_compliance_summaries_flush v03).
  IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
    RETURN;
  END IF;

  -- The run's grace for a new fixable critical (owner decision 7; the vulnerabilities.run_grace_days setting), read only
  -- when there is something to recount. A value that is not a whole number of days (Setting writes only those) reads as
  -- the default rather than failing every flush.
  grace := COALESCE((SELECT CASE WHEN jsonb_typeof(st.value) = 'number' AND st.value::text ~ '^[0-9]{1,4}$' THEN (st.value::text)::integer END
                       FROM settings st WHERE st.key = 'vulnerabilities.run_grace_days'), 7) * interval '1 day';

  -- Lock first, in host order, then count in a later statement: under READ COMMITTED that statement takes a new
  -- snapshot, so a transaction that waited here for another one counts what that one committed. Two transactions
  -- changing one host's rows at once therefore leave the counts of both, whichever commits first.
  PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (host_ids) ORDER BY s.host_id FOR UPDATE;

  UPDATE host_compliance_summaries s
     SET cis_passed = c.cis_passed, cis_failed = c.cis_failed, cis_not_readable = c.cis_not_readable,
         cis_critical = c.cis_critical, cis_high = c.cis_high, cis_medium = c.cis_medium, cis_low = c.cis_low,
         vuln_critical = c.vuln_critical, vuln_high = c.vuln_high, vuln_medium = c.vuln_medium, vuln_low = c.vuln_low,
         vuln_unknown = c.vuln_unknown, vuln_evaluated = c.vuln_evaluated,
         vuln_fix = c.vuln_fix, vuln_attention = c.vuln_attention, vuln_low_risk = c.vuln_low_risk, vuln_ignorable = c.vuln_ignorable,
         vuln_kev_open = c.vuln_kev_open,
         exposure_tier = c.exposure_tier, exposure_points = c.exposure_points, vuln_kev_advisories = c.vuln_kev_advisories,
         vuln_fix_critical = c.vuln_fix_critical, vuln_attention_undecided = c.vuln_attention_undecided,
         work_upgrades = c.work_upgrades, work_kernel_install = c.work_kernel_install, work_reboot = c.work_reboot, work_items = c.work_items,
         fixable_critical_since = r.fixable_since, no_fixable_critical_since = r.run_since
    FROM host_compliance_counts(host_ids) c
    JOIN host_compliance_summaries o ON o.host_id = c.host_id
    CROSS JOIN LATERAL (
      SELECT CASE WHEN c.exposure_tier IS NULL THEN NULL
                  WHEN c.vuln_fix_critical > 0 THEN COALESCE(o.fixable_critical_since, now())
             END AS fixable_since,
             CASE WHEN c.exposure_tier IS NULL THEN NULL
                  WHEN c.vuln_fix_critical > 0 THEN o.no_fixable_critical_since
                  WHEN o.fixable_critical_since IS NULL THEN COALESCE(o.no_fixable_critical_since, now())
                  WHEN o.no_fixable_critical_since <= o.fixable_critical_since AND now() - o.fixable_critical_since < grace THEN o.no_fixable_critical_since
                  ELSE now()
             END AS run_since
    ) r
   WHERE s.host_id = c.host_id
     AND (s.cis_passed, s.cis_failed, s.cis_not_readable, s.cis_critical, s.cis_high, s.cis_medium, s.cis_low,
          s.vuln_critical, s.vuln_high, s.vuln_medium, s.vuln_low, s.vuln_unknown, s.vuln_evaluated,
          s.vuln_fix, s.vuln_attention, s.vuln_low_risk, s.vuln_ignorable, s.vuln_kev_open,
          s.exposure_tier, s.exposure_points, s.vuln_kev_advisories, s.vuln_fix_critical, s.vuln_attention_undecided,
          s.work_upgrades, s.work_kernel_install, s.work_reboot, s.work_items, s.fixable_critical_since, s.no_fixable_critical_since)
         IS DISTINCT FROM
         (c.cis_passed, c.cis_failed, c.cis_not_readable, c.cis_critical, c.cis_high, c.cis_medium, c.cis_low,
          c.vuln_critical, c.vuln_high, c.vuln_medium, c.vuln_low, c.vuln_unknown, c.vuln_evaluated,
          c.vuln_fix, c.vuln_attention, c.vuln_low_risk, c.vuln_ignorable, c.vuln_kev_open,
          c.exposure_tier, c.exposure_points, c.vuln_kev_advisories, c.vuln_fix_critical, c.vuln_attention_undecided,
          c.work_upgrades, c.work_kernel_install, c.work_reboot, c.work_items, r.fixable_since, r.run_since);
END;
$$;
