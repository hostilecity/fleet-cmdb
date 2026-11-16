CREATE OR REPLACE FUNCTION host_compliance_summaries_changed()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  counted CONSTANT text[] := ARRAY['pass', 'fail', 'not_readable'];
  open_states CONSTANT text[] := ARRAY['open', 'reopened'];
  host_ids bigint[];
BEGIN
  -- Notes the hosts whose summaries a change can move (#193), for host_compliance_summaries_flush at commit. No
  -- summary row is locked here. Statement triggers pick out the rows that changed in a way the summary can see.
  --
  -- Every query over a transition table (old_rows, new_rows) runs through EXECUTE, so it is planned for the rows this
  -- statement changed (v02, #224). A static query keeps the plan it got the first time in the session: one without
  -- parameters always reuses its generic plan, and the transition tables' size is frozen into it. So after a one-row
  -- update, a 20,000-row UPDATE of hosts ran a nested loop for 29 to 40 s instead of a merge join for about 0.1 s.

  -- hosts (statement): a new host, or a change to a field the fleet list shows, sorts, or filters by (a sync).
  -- Liveness is in host_liveness (v03, #192; its transition-table queries run through EXECUTE as in v02, #224).
  IF TG_TABLE_NAME = 'hosts' THEN
    IF TG_OP = 'INSERT' THEN
      EXECUTE 'SELECT ARRAY(SELECT n.id FROM new_rows n)' INTO host_ids;
      PERFORM host_compliance_summaries_mark(host_ids, 1::smallint);
    ELSE
      EXECUTE $q$
        SELECT ARRAY(SELECT n.id FROM old_rows o JOIN new_rows n ON n.id = o.id
                      WHERE (o.name, o.hostname, o.tags, o.agent_version, o.enrollment_state)
                            IS DISTINCT FROM (n.name, n.hostname, n.tags, n.agent_version, n.enrollment_state))
      $q$ INTO host_ids;
      PERFORM host_compliance_summaries_mark(host_ids, 1::smallint);
    END IF;
    RETURN NULL;
  END IF;

  -- host_liveness (row, its status changed; #192): the status sort key only. A row trigger with a WHEN clause, so the
  -- heartbeats that leave the status as it was, nearly all of them, queue nothing and call nothing.
  IF TG_TABLE_NAME = 'host_liveness' THEN
    PERFORM host_compliance_summaries_mark(ARRAY[CASE TG_OP WHEN 'DELETE' THEN OLD.host_id ELSE NEW.host_id END], 2::smallint);
    RETURN NULL;
  END IF;

  -- host_inventories (row, its operating system name changed).
  IF TG_TABLE_NAME = 'host_inventories' THEN
    PERFORM host_compliance_summaries_mark(CASE TG_OP WHEN 'INSERT' THEN ARRAY[NEW.host_id] WHEN 'DELETE' THEN ARRAY[OLD.host_id]
                                                      ELSE ARRAY[OLD.host_id, NEW.host_id] END, 1::smallint);
    RETURN NULL;
  END IF;

  -- advisories (statement): a new severity moves the counts of every host with an open finding for it, which can
  -- be the whole fleet. Those hosts are queued, not recounted here: an import is one long transaction, and must not
  -- hold their summary rows. ComplianceSummaryRecountJob recounts them in short sorted batches after it commits.
  IF TG_TABLE_NAME = 'advisories' THEN
    EXECUTE $q$
      INSERT INTO host_compliance_recounts (host_id)
      SELECT DISTINCT f.host_id
        FROM old_rows o JOIN new_rows n ON n.id = o.id
        JOIN vulnerability_findings f ON f.advisory_id = n.id
       WHERE o.severity <> n.severity AND f.state = ANY ($1)
      ON CONFLICT DO NOTHING
    $q$ USING open_states;
    RETURN NULL;
  END IF;

  -- host_vulnerability_evaluations (row, its state changed).
  IF TG_TABLE_NAME = 'host_vulnerability_evaluations' THEN
    host_ids := CASE TG_OP WHEN 'INSERT' THEN ARRAY[NEW.host_id] WHEN 'DELETE' THEN ARRAY[OLD.host_id] ELSE ARRAY[OLD.host_id, NEW.host_id] END;

  -- cis_rules (row, its current version changed): a failure that names no version takes the current one's severity.
  ELSIF TG_TABLE_NAME = 'cis_rules' THEN
    host_ids := ARRAY(SELECT DISTINCT r.host_id FROM cis_results r
                       WHERE r.cis_rule_id = NEW.id AND r.result = 'fail' AND r.cis_rule_version_id IS NULL);

  -- cis_results (statement): a counted result appeared or went, a result changed, or the rule version a failure is
  -- counted under changed.
  ELSIF TG_TABLE_NAME = 'cis_results' THEN
    IF TG_OP = 'INSERT' THEN
      EXECUTE 'SELECT ARRAY(SELECT DISTINCT n.host_id FROM new_rows n WHERE n.result = ANY ($1))' INTO host_ids USING counted;
    ELSIF TG_OP = 'DELETE' THEN
      EXECUTE 'SELECT ARRAY(SELECT DISTINCT o.host_id FROM old_rows o WHERE o.result = ANY ($1))' INTO host_ids USING counted;
    ELSE
      EXECUTE $q$
        SELECT ARRAY(
          SELECT DISTINCT v.host_id
            FROM old_rows o JOIN new_rows n ON n.id = o.id, LATERAL (VALUES (o.host_id), (n.host_id)) v(host_id)
           WHERE o.host_id <> n.host_id OR o.cis_rule_id <> n.cis_rule_id
              OR (o.result <> n.result AND (o.result = ANY ($1) OR n.result = ANY ($1)))
              OR (n.result = 'fail' AND o.cis_rule_version_id IS DISTINCT FROM n.cis_rule_version_id))
      $q$ INTO host_ids USING counted;
    END IF;

  -- vulnerability_findings (statement): a finding opened, reopened, or resolved, or an open one moved.
  ELSIF TG_TABLE_NAME = 'vulnerability_findings' THEN
    IF TG_OP = 'INSERT' THEN
      EXECUTE 'SELECT ARRAY(SELECT DISTINCT n.host_id FROM new_rows n WHERE n.state = ANY ($1))' INTO host_ids USING open_states;
    ELSIF TG_OP = 'DELETE' THEN
      EXECUTE 'SELECT ARRAY(SELECT DISTINCT o.host_id FROM old_rows o WHERE o.state = ANY ($1))' INTO host_ids USING open_states;
    ELSE
      EXECUTE $q$
        SELECT ARRAY(
          SELECT DISTINCT v.host_id
            FROM old_rows o JOIN new_rows n ON n.id = o.id, LATERAL (VALUES (o.host_id), (n.host_id)) v(host_id)
           WHERE (o.state = ANY ($1) OR n.state = ANY ($1))
             AND ((o.state = ANY ($1)) <> (n.state = ANY ($1)) OR o.advisory_id <> n.advisory_id OR o.host_id <> n.host_id))
      $q$ INTO host_ids USING open_states;
    END IF;
  END IF;

  PERFORM host_compliance_summaries_mark(host_ids, 4::smallint);
  RETURN NULL;
END;
$$;
