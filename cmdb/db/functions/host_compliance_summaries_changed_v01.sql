CREATE OR REPLACE FUNCTION host_compliance_summaries_changed()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  counted CONSTANT text[] := ARRAY['pass', 'fail', 'not_readable'];
  open_states CONSTANT text[] := ARRAY['open', 'reopened'];
  host_ids bigint[];
BEGIN
  -- Keeps host_compliance_summaries right in the transaction that changes what it is built from (#193). Statement
  -- triggers find the hosts whose rows changed in a way the summary can see, and each is synced or recounted once.

  -- hosts (statement): a new host, or a change to a field the fleet list shows, sorts, or filters by.
  IF TG_TABLE_NAME = 'hosts' THEN
    IF TG_OP = 'INSERT' THEN
      host_ids := ARRAY(SELECT n.id FROM new_rows n);
    ELSE
      host_ids := ARRAY(
        SELECT n.id FROM old_rows o JOIN new_rows n ON n.id = o.id
         WHERE (o.name, o.hostname, o.tags, o.agent_version, o.enrollment_state, o.liveness_status)
               IS DISTINCT FROM (n.name, n.hostname, n.tags, n.agent_version, n.enrollment_state, n.liveness_status));
    END IF;
    PERFORM host_compliance_summaries_sync(host_ids);
    RETURN NULL;
  END IF;

  -- host_inventories (row, its operating system name changed).
  IF TG_TABLE_NAME = 'host_inventories' THEN
    PERFORM host_compliance_summaries_sync(CASE TG_OP WHEN 'INSERT' THEN ARRAY[NEW.host_id] WHEN 'DELETE' THEN ARRAY[OLD.host_id]
                                                      ELSE ARRAY[OLD.host_id, NEW.host_id] END);
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
      host_ids := ARRAY(SELECT DISTINCT n.host_id FROM new_rows n WHERE n.result = ANY (counted));
    ELSIF TG_OP = 'DELETE' THEN
      host_ids := ARRAY(SELECT DISTINCT o.host_id FROM old_rows o WHERE o.result = ANY (counted));
    ELSE
      host_ids := ARRAY(
        SELECT DISTINCT v.host_id
          FROM old_rows o JOIN new_rows n ON n.id = o.id, LATERAL (VALUES (o.host_id), (n.host_id)) v(host_id)
         WHERE o.host_id <> n.host_id OR o.cis_rule_id <> n.cis_rule_id
            OR (o.result <> n.result AND (o.result = ANY (counted) OR n.result = ANY (counted)))
            OR (n.result = 'fail' AND o.cis_rule_version_id IS DISTINCT FROM n.cis_rule_version_id));
    END IF;

  -- vulnerability_findings (statement): a finding opened, reopened, or resolved, or an open one moved.
  ELSIF TG_TABLE_NAME = 'vulnerability_findings' THEN
    IF TG_OP = 'INSERT' THEN
      host_ids := ARRAY(SELECT DISTINCT n.host_id FROM new_rows n WHERE n.state = ANY (open_states));
    ELSIF TG_OP = 'DELETE' THEN
      host_ids := ARRAY(SELECT DISTINCT o.host_id FROM old_rows o WHERE o.state = ANY (open_states));
    ELSE
      host_ids := ARRAY(
        SELECT DISTINCT v.host_id
          FROM old_rows o JOIN new_rows n ON n.id = o.id, LATERAL (VALUES (o.host_id), (n.host_id)) v(host_id)
         WHERE (o.state = ANY (open_states) OR n.state = ANY (open_states))
           AND ((o.state = ANY (open_states)) <> (n.state = ANY (open_states)) OR o.advisory_id <> n.advisory_id OR o.host_id <> n.host_id));
    END IF;

  -- advisories (statement): a new severity moves the counts of every host with an open finding for it.
  ELSIF TG_TABLE_NAME = 'advisories' THEN
    host_ids := ARRAY(
      SELECT DISTINCT f.host_id
        FROM old_rows o JOIN new_rows n ON n.id = o.id
        JOIN vulnerability_findings f ON f.advisory_id = n.id
       WHERE o.severity <> n.severity AND f.state = ANY (open_states));
  END IF;

  PERFORM host_compliance_summaries_refresh(host_ids);
  RETURN NULL;
END;
$$;
