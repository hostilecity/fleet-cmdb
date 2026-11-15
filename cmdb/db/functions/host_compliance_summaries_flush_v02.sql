CREATE OR REPLACE FUNCTION host_compliance_summaries_flush()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  all_ids bigint[];
  sync_ids bigint[];
  status_ids bigint[];
  count_ids bigint[];
BEGIN
  -- Runs once a transaction, at commit (a deferred constraint trigger on host_compliance_flushes, #193): syncs and
  -- recounts every host the transaction marked. Every summary row it needs is locked in one statement, in host id
  -- order, so locks are held only while the transaction commits, and always taken in the same order: two
  -- transactions can wait for each other's commit, but never deadlock on summaries, and a transaction never waits
  -- on a summary row in the middle of its work.
  DELETE FROM host_compliance_flushes WHERE xact_id = NEW.xact_id;
  WITH taken AS (DELETE FROM host_compliance_pending WHERE xact_id = NEW.xact_id RETURNING host_id, kinds)
  SELECT array_agg(host_id ORDER BY host_id),
         array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 1 <> 0),
         array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 3 = 2),
         array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 4 <> 0)
    INTO all_ids, sync_ids, status_ids, count_ids
    FROM taken;
  IF all_ids IS NULL THEN
    RETURN NULL;
  END IF;

  PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (all_ids) ORDER BY s.host_id FOR UPDATE;

  -- A host with no summary row yet (made in this transaction, or not reached by the migration's fill) is synced,
  -- which makes the row.
  sync_ids := ARRAY(SELECT DISTINCT h FROM unnest(COALESCE(sync_ids, '{}'::bigint[]) || ARRAY(
                SELECT a FROM unnest(all_ids) a WHERE NOT EXISTS (SELECT 1 FROM host_compliance_summaries s WHERE s.host_id = a))) h ORDER BY h);
  PERFORM host_compliance_summaries_sync(sync_ids);

  -- Liveness alone moves only the status sort key: no join to hosts (the summary has its enrollment state), no regex,
  -- no rewrite of the other copies. The status is in host_liveness (#192); no row there is no heartbeat yet.
  UPDATE host_compliance_summaries s
     SET status_rank = host_compliance_status_rank(s.enrollment_state, l.liveness_status)
    FROM (SELECT a AS host_id FROM unnest(status_ids) a) c
    LEFT JOIN host_liveness l ON l.host_id = c.host_id
   WHERE s.host_id = c.host_id AND NOT s.host_id = ANY (sync_ids)
     AND s.status_rank IS DISTINCT FROM host_compliance_status_rank(s.enrollment_state, l.liveness_status);

  PERFORM host_compliance_summaries_refresh(count_ids);
  RETURN NULL;
END;
$$;
