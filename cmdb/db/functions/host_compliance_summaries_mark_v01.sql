CREATE OR REPLACE FUNCTION host_compliance_summaries_mark(host_ids bigint[], kinds smallint)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  -- Notes that this transaction changed what the hosts' summaries are built from (#193). kinds is a bit set: 1 the
  -- host's own fields or operating system (a sync), 2 its liveness only (the status sort key), 4 its counts. Nothing
  -- here locks a summary row: host_compliance_summaries_flush does it once, sorted, at commit. The rows are keyed by
  -- transaction, so two transactions marking one host never wait for each other.
  IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
    RETURN;
  END IF;

  INSERT INTO host_compliance_pending AS p (xact_id, host_id, kinds)
  SELECT txid_current(), h.id, kinds FROM (SELECT DISTINCT unnest(host_ids) AS id) h
  ON CONFLICT (xact_id, host_id) DO UPDATE SET kinds = p.kinds | EXCLUDED.kinds
   WHERE p.kinds | EXCLUDED.kinds <> p.kinds;

  -- One row a transaction; its deferred constraint trigger runs the flush once, at commit.
  INSERT INTO host_compliance_flushes (xact_id) VALUES (txid_current()) ON CONFLICT DO NOTHING;
END;
$$;
